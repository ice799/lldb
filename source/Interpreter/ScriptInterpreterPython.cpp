//===-- ScriptInterpreterPython.cpp -----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// In order to guarantee correct working with Python, Python.h *MUST* be
// the *FIRST* header file included:

#include <Python.h>

#include "lldb/Interpreter/ScriptInterpreterPython.h"


#include <sys/ioctl.h>
#include <termios.h>
#include <stdlib.h>
#include <stdio.h>

#include <string>

#include "lldb/Breakpoint/Breakpoint.h"
#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/FileSpec.h"
#include "lldb/Core/InputReader.h"
#include "lldb/Core/Stream.h"
#include "lldb/Core/StreamString.h"
#include "lldb/Core/Timer.h"
#include "lldb/Host/Host.h"
#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Target/Process.h"

extern "C" void init_lldb (void);

using namespace lldb;
using namespace lldb_private;

const char embedded_interpreter_string[] =
"import readline\n\
import code\n\
import sys\n\
import traceback\n\
\n\
class SimpleREPL(code.InteractiveConsole):\n\
   def __init__(self, prompt, dict):\n\
       code.InteractiveConsole.__init__(self,dict)\n\
       self.prompt = prompt\n\
       self.loop_exit = False\n\
       self.dict = dict\n\
\n\
   def interact(self):\n\
       try:\n\
           sys.ps1\n\
       except AttributeError:\n\
           sys.ps1 = \">>> \"\n\
       try:\n\
           sys.ps2\n\
       except AttributeError:\n\
           sys.ps2 = \"... \"\n\
\n\
       while not self.loop_exit:\n\
           try:\n\
               self.read_py_command()\n\
           except (SystemExit, EOFError):\n\
               # EOF while in Python just breaks out to top level.\n\
               self.write('\\n')\n\
               self.loop_exit = True\n\
               break\n\
           except KeyboardInterrupt:\n\
               self.write(\"\\nKeyboardInterrupt\\n\")\n\
               self.resetbuffer()\n\
               more = 0\n\
           except:\n\
               traceback.print_exc()\n\
\n\
   def process_input (self, in_str):\n\
      # Canonicalize the format of the input string\n\
      temp_str = in_str\n\
      temp_str.strip(' \t')\n\
      words = temp_str.split()\n\
      temp_str = ('').join(words)\n\
\n\
      # Check the input string to see if it was the quit\n\
      # command.  If so, intercept it, so that it doesn't\n\
      # close stdin on us!\n\
      if (temp_str.lower() == \"quit()\" or temp_str.lower() == \"exit()\"):\n\
         self.loop_exit = True\n\
         in_str = \"raise SystemExit \"\n\
      return in_str\n\
\n\
   def my_raw_input (self, prompt):\n\
      stream = sys.stdout\n\
      stream.write (prompt)\n\
      stream.flush ()\n\
      try:\n\
         line = sys.stdin.readline()\n\
      except KeyboardInterrupt:\n\
         line = \" \\n\"\n\
      except (SystemExit, EOFError):\n\
         line = \"quit()\\n\"\n\
      if not line:\n\
         raise EOFError\n\
      if line[-1] == '\\n':\n\
         line = line[:-1]\n\
      return line\n\
\n\
   def read_py_command(self):\n\
       # Read off a complete Python command.\n\
       more = 0\n\
       while 1:\n\
           if more:\n\
               prompt = sys.ps2\n\
           else:\n\
               prompt = sys.ps1\n\
           line = self.my_raw_input(prompt)\n\
           # Can be None if sys.stdin was redefined\n\
           encoding = getattr(sys.stdin, \"encoding\", None)\n\
           if encoding and not isinstance(line, unicode):\n\
               line = line.decode(encoding)\n\
           line = self.process_input (line)\n\
           more = self.push(line)\n\
           if not more:\n\
               break\n\
\n\
def run_python_interpreter (dict):\n\
   # Pass in the dictionary, for continuity from one session to the next.\n\
   repl = SimpleREPL('>>> ', dict)\n\
   repl.interact()\n";

static int
_check_and_flush (FILE *stream)
{
  int prev_fail = ferror (stream);
  return fflush (stream) || prev_fail ? EOF : 0;
}

ScriptInterpreterPython::ScriptInterpreterPython () :
    ScriptInterpreter (eScriptLanguagePython),
    m_compiled_module (NULL),
    m_termios_valid (false)
{

    Timer scoped_timer (__PRETTY_FUNCTION__, __PRETTY_FUNCTION__);
    // Find the module that owns this code and use that path we get to
    // set the PYTHONPATH appropriately.

    FileSpec this_module (Host::GetModuleFileSpecForHostAddress ((void *)init_lldb));
    std::string python_path;

    if (this_module.GetDirectory())
    {
        // Append the directory that the module that loaded this code
        // belongs to
        python_path += this_module.GetDirectory().AsCString("");

#if defined (__APPLE__)
        // If we are running on MacOSX we might be in a framework and should
        // add an appropriate path so Resource can be found in a bundle

        if (::strstr(this_module.GetDirectory().AsCString(""), ".framework"))
        {
            python_path.append(1, ':');
            python_path.append(this_module.GetDirectory().AsCString(""));
            python_path.append("/Resources/Python");
        }
#endif
        // The the PYTHONPATH environment variable so that Python can find
        // our lldb.py module and our _lldb.so.
        ::setenv ("PYTHONPATH", python_path.c_str(), 1);
    }

    Py_Initialize ();

    PyObject *compiled_module = Py_CompileString (embedded_interpreter_string, "embedded_interpreter.py",
                                                  Py_file_input);

    m_compiled_module = static_cast<void*>(compiled_module);

    init_lldb ();

    // Update the path python uses to search for modules to include the current directory.

    int success = PyRun_SimpleString ("import sys");
    success = PyRun_SimpleString ("sys.path.append ('.')");
    if (success == 0)
    {
        // Import the Script Bridge module.
        success =  PyRun_SimpleString ("from lldb import *");
    }

    const char *pty_slave_name = GetScriptInterpreterPtyName ();
    FILE *out_fh = Debugger::GetSharedInstance().GetOutputFileHandle();
    
    PyObject *pmod = PyImport_ExecCodeModule(
                         const_cast<char*>("embedded_interpreter"),
                         static_cast<PyObject*>(m_compiled_module));
    if (pmod != NULL)
    {
        PyRun_SimpleString ("ConsoleDict = locals()");
        PyRun_SimpleString ("from embedded_interpreter import run_python_interpreter");
        PyRun_SimpleString ("import sys");
        PyRun_SimpleString ("from termios import *");
        PyRun_SimpleString ("old_stdin = sys.stdin");
      
        StreamString run_string;
        run_string.Printf ("new_stdin = open('%s', 'r')", pty_slave_name);
        PyRun_SimpleString (run_string.GetData());
        PyRun_SimpleString ("sys.stdin = new_stdin");

        PyRun_SimpleString ("old_stdout = sys.stdout");
        
        if (out_fh != NULL)
        {
            PyObject *new_sysout = PyFile_FromFile (out_fh, (char *) "", (char *) "w", 
                                                        _check_and_flush);
            PyObject *sysmod = PyImport_AddModule ("sys");
            PyObject *sysdict = PyModule_GetDict (sysmod);

            if ((new_sysout != NULL)
                && (sysmod != NULL)
                && (sysdict != NULL))
            {
                PyDict_SetItemString (sysdict, "stdout", new_sysout);
            }

            if (PyErr_Occurred())
                PyErr_Clear();
        }

        PyRun_SimpleString ("new_mode = tcgetattr(new_stdin)");
        PyRun_SimpleString ("new_mode[3] = new_mode[3] | ECHO | ICANON");
        PyRun_SimpleString ("new_mode[6][VEOF] = 255");
        PyRun_SimpleString ("tcsetattr (new_stdin, TCSANOW, new_mode)");
    }


}

ScriptInterpreterPython::~ScriptInterpreterPython ()
{
    PyRun_SimpleString ("sys.stdin = old_stdin");
    PyRun_SimpleString ("sys.stdout = old_stdout");
    Py_Finalize ();
}

void
ScriptInterpreterPython::ExecuteOneLine (const std::string& line, FILE *out, FILE *err)
{
    int success;

    success = PyRun_SimpleString (line.c_str());
    if (success != 0)
    {
        fprintf (err, "error: python failed attempting to evaluate '%s'\n", line.c_str());
    }
}



size_t
ScriptInterpreterPython::InputReaderCallback
(
    void *baton, 
    InputReader *reader, 
    lldb::InputReaderAction notification,
    const char *bytes, 
    size_t bytes_len
)
{
    if (baton == NULL)
        return 0;

    ScriptInterpreterPython *interpreter = (ScriptInterpreterPython *) baton;            
    switch (notification)
    {
    case eInputReaderActivate:
        {
            // Save terminal settings if we can
            interpreter->m_termios_valid = ::tcgetattr (::fileno (reader->GetInputFileHandle()), 
                                                        &interpreter->m_termios) == 0;
            struct termios tmp_termios;
            if (::tcgetattr (::fileno (reader->GetInputFileHandle()), &tmp_termios) == 0)
            {
                tmp_termios.c_cc[VEOF] = _POSIX_VDISABLE;
                ::tcsetattr (::fileno (reader->GetInputFileHandle()), TCSANOW, &tmp_termios);
            }
        }
        break;

    case eInputReaderDeactivate:
        break;

    case eInputReaderReactivate:
        break;

    case eInputReaderGotToken:
        if (bytes && bytes_len)
        {
            if ((int) bytes[0] == 4)
                ::write (interpreter->GetMasterFileDescriptor(), "quit()", 6);
            else
                ::write (interpreter->GetMasterFileDescriptor(), bytes, bytes_len);
        }
        ::write (interpreter->GetMasterFileDescriptor(), "\n", 1);
        break;
        
    case eInputReaderDone:
        // Send a control D to the script interpreter
        //::write (interpreter->GetMasterFileDescriptor(), "\nquit()\n", strlen("\nquit()\n"));
        // Write a newline out to the reader output
        //::fwrite ("\n", 1, 1, out_fh);
        // Restore terminal settings if they were validly saved
        if (interpreter->m_termios_valid)
        {
            ::tcsetattr (::fileno (reader->GetInputFileHandle()), 
                         TCSANOW,
                         &interpreter->m_termios);
        }
        break;
    }

    return bytes_len;
}


void
ScriptInterpreterPython::ExecuteInterpreterLoop (FILE *out, FILE *err)
{
    Timer scoped_timer (__PRETTY_FUNCTION__, __PRETTY_FUNCTION__);

    InputReaderSP reader_sp (new InputReader());
    if (reader_sp)
    {
        Error error (reader_sp->Initialize (ScriptInterpreterPython::InputReaderCallback,
                                            this,                         // baton
                                            eInputReaderGranularityLine,  // token size, to pass to callback function
                                            NULL,                         // end token
                                            NULL,                         // prompt
                                            true));                       // echo input
     
        if (error.Success())
        {
            Debugger::GetSharedInstance().PushInputReader (reader_sp);
            ExecuteOneLine ("run_python_interpreter(ConsoleDict)", out, err);
            Debugger::GetSharedInstance().PopInputReader (reader_sp);
        }
    }
}

bool
ScriptInterpreterPython::ExecuteOneLineWithReturn (const char *in_string,
                                                   ScriptInterpreter::ReturnType return_type,
                                                   void *ret_value)
{
    PyObject *py_return = NULL;
    PyObject *mainmod = PyImport_AddModule ("__main__");
    PyObject *globals = PyModule_GetDict (mainmod);
    PyObject *locals = globals;
    PyObject *py_error = NULL;
    bool ret_success;
    int success;

    if (in_string != NULL)
    {
        py_return = PyRun_String (in_string, Py_eval_input, globals, locals);
        if (py_return == NULL)
        {
            py_error = PyErr_Occurred ();
            if (py_error != NULL)
                PyErr_Clear ();

            py_return = PyRun_String (in_string, Py_single_input, globals, locals);
        }

        if (py_return != NULL)
        {
            switch (return_type)
            {
                case eCharPtr: // "char *"
                {
                    const char format[3] = "s#";
                    success = PyArg_Parse (py_return, format, (char **) &ret_value);
                    break;
                }
                case eBool:
                {
                    const char format[2] = "b";
                    success = PyArg_Parse (py_return, format, (bool *) ret_value);
                    break;
                }
                case eShortInt:
                {
                    const char format[2] = "h";
                    success = PyArg_Parse (py_return, format, (short *) ret_value);
                    break;
                }
                case eShortIntUnsigned:
                {
                    const char format[2] = "H";
                    success = PyArg_Parse (py_return, format, (unsigned short *) ret_value);
                    break;
                }
                case eInt:
                {
                    const char format[2] = "i";
                    success = PyArg_Parse (py_return, format, (int *) ret_value);
                    break;
                }
                case eIntUnsigned:
                {
                    const char format[2] = "I";
                    success = PyArg_Parse (py_return, format, (unsigned int *) ret_value);
                    break;
                }
                case eLongInt:
                {
                    const char format[2] = "l";
                    success = PyArg_Parse (py_return, format, (long *) ret_value);
                    break;
                }
                case eLongIntUnsigned:
                {
                    const char format[2] = "k";
                    success = PyArg_Parse (py_return, format, (unsigned long *) ret_value);
                    break;
                }
                case eLongLong:
                {
                    const char format[2] = "L";
                    success = PyArg_Parse (py_return, format, (long long *) ret_value);
                    break;
                }
                case eLongLongUnsigned:
                {
                    const char format[2] = "K";
                    success = PyArg_Parse (py_return, format, (unsigned long long *) ret_value);
                    break;
                }
                case eFloat:
                {
                    const char format[2] = "f";
                    success = PyArg_Parse (py_return, format, (float *) ret_value);
                    break;
                }
                case eDouble:
                {
                    const char format[2] = "d";
                    success = PyArg_Parse (py_return, format, (double *) ret_value);
                    break;
                }
                case eChar:
                {
                    const char format[2] = "c";
                    success = PyArg_Parse (py_return, format, (char *) ret_value);
                    break;
                }
                default:
                  {}
            }
            Py_DECREF (py_return);
            if (success)
                ret_success = true;
            else
                ret_success = false;
        }
    }

    py_error = PyErr_Occurred();
    if (py_error != NULL)
    {
        if (PyErr_GivenExceptionMatches (py_error, PyExc_SyntaxError))
            PyErr_Print ();
        PyErr_Clear();
        ret_success = false;
    }

    return ret_success;
}

bool
ScriptInterpreterPython::ExecuteMultipleLines (const char *in_string)
{
    bool success = false;
    PyObject *py_return = NULL;
    PyObject *mainmod = PyImport_AddModule ("__main__");
    PyObject *globals = PyModule_GetDict (mainmod);
    PyObject *locals = globals;
    PyObject *py_error = NULL;

    if (in_string != NULL)
    {
        struct _node *compiled_node = PyParser_SimpleParseString (in_string, Py_file_input);
        if (compiled_node)
        {
            PyCodeObject *compiled_code = PyNode_Compile (compiled_node, "temp.py");
            if (compiled_code)
            {
                py_return = PyEval_EvalCode (compiled_code, globals, locals);
                if (py_return != NULL)
                {
                    success = true;
                    Py_DECREF (py_return);
                }
            }
        }
    }

    py_error = PyErr_Occurred ();
    if (py_error != NULL)
    {
        if (PyErr_GivenExceptionMatches (py_error, PyExc_SyntaxError))
            PyErr_Print ();
        PyErr_Clear();
        success = false;
    }

    return success;
}

static const char *g_reader_instructions = "Enter your Python command(s). Type 'DONE' to end.";

size_t
ScriptInterpreterPython::GenerateBreakpointOptionsCommandCallback
(
    void *baton, 
    InputReader *reader, 
    lldb::InputReaderAction notification,
    const char *bytes, 
    size_t bytes_len
)
{
  static StringList commands_in_progress;

    FILE *out_fh = reader->GetOutputFileHandle();
    switch (notification)
    {
    case eInputReaderActivate:
        {
            commands_in_progress.Clear();
            if (out_fh)
            {
                ::fprintf (out_fh, "%s\n", g_reader_instructions);
                if (reader->GetPrompt())
                    ::fprintf (out_fh, "%s", reader->GetPrompt());
            }
        }
        break;

    case eInputReaderDeactivate:
        break;

    case eInputReaderReactivate:
        if (reader->GetPrompt() && out_fh)
            ::fprintf (out_fh, "%s", reader->GetPrompt());
        break;

    case eInputReaderGotToken:
        {
            std::string temp_string (bytes, bytes_len);
            commands_in_progress.AppendString (temp_string.c_str());
            if (out_fh && !reader->IsDone() && reader->GetPrompt())
                ::fprintf (out_fh, "%s", reader->GetPrompt());
        }
        break;

    case eInputReaderDone:
        {
            BreakpointOptions *bp_options = (BreakpointOptions *)baton;
            std::auto_ptr<BreakpointOptions::CommandData> data_ap(new BreakpointOptions::CommandData());
            data_ap->user_source.AppendList (commands_in_progress);
            if (data_ap.get())
            {
                ScriptInterpreter *interpreter = Debugger::GetSharedInstance().GetCommandInterpreter().GetScriptInterpreter();
                if (interpreter)
                {
                    if (interpreter->GenerateBreakpointCommandCallbackData (data_ap->user_source, 
                                                                            data_ap->script_source))
                    {
                        if (data_ap->script_source.GetSize() == 1)
                        {
                            BatonSP baton_sp (new BreakpointOptions::CommandBaton (data_ap.release()));
                            bp_options->SetCallback (ScriptInterpreterPython::BreakpointCallbackFunction, baton_sp);
                        }
                    }
                }
                else
                {
                    // FIXME:  Error processing.
                }
            }
        }
        break;
        
    }

    return bytes_len;
}

void
ScriptInterpreterPython::CollectDataForBreakpointCommandCallback (BreakpointOptions *bp_options,
                                                                  CommandReturnObject &result)
{
    InputReaderSP reader_sp (new InputReader ());

    if (reader_sp)
    {
        Error err = reader_sp->Initialize (
                ScriptInterpreterPython::GenerateBreakpointOptionsCommandCallback,
                bp_options,                 // baton
                eInputReaderGranularityLine, // token size, for feeding data to callback function
                "DONE",                     // end token
                "> ",                       // prompt
                true);                      // echo input
    
        if (err.Success())
            Debugger::GetSharedInstance().PushInputReader (reader_sp);
        else
        {
            result.AppendError (err.AsCString());
            result.SetStatus (eReturnStatusFailed);
        }
    }
    else
    {
        result.AppendError("out of memory");
        result.SetStatus (eReturnStatusFailed);
    }
}

bool
ScriptInterpreterPython::ExportFunctionDefinitionToInterpreter (StringList &function_def)
{
    // Convert StringList to one long, newline delimited, const char *.
    std::string function_def_string;

    int num_lines = function_def.GetSize();

    for (int i = 0; i < num_lines; ++i)
    {
        function_def_string.append (function_def.GetStringAtIndex(i));
        if (function_def_string.at (function_def_string.length() - 1) != '\n')
            function_def_string.append ("\n");

    }

    return ExecuteMultipleLines (function_def_string.c_str());
}

bool
ScriptInterpreterPython::GenerateBreakpointCommandCallbackData (StringList &user_input, StringList &callback_data)
{
    static int num_created_functions = 0;

    user_input.RemoveBlankLines ();
    int num_lines = user_input.GetSize();
    std::string last_function_call;

    // Go through lines of input looking for any function definitions. For each function definition found,
    // export the function definition to Python, create a potential function call for the function, and
    // mark the lines of the function to be removed from the user input.

    for (int i = 0; i < num_lines; ++i)
    {
        int function_start = i;
        std::string current_str = user_input.GetStringAtIndex (i);
        const char *current_line = current_str.c_str();
        int len = 0;
        if (current_line)
            len = strlen (current_line);

        // Check to see if the current line is the start of a Python function definition.
        if (len > 4 && strncmp (current_line, "def ", 4) == 0)
        {
            // We've found the first line of a function. First, get the function name.

            // Skip over the 'def '.
            char *start = (char *) current_line + 4;

            // Skip over white space.
            while (start[0] == ' ' || start[0] == '\t')
              ++start;

            // Find the end of the function name.
            char *end = start;
            while (isalnum (end[0]) || end[0] == '_')
              ++end;

            int name_len = end - start;
            std::string func_name = current_str.substr (4, name_len);

            // Now to find the last line of the function.  That will be the first line that does not begin with
            // any white space (thanks to Python's indentation rules).
            ++i;
            bool found = false;
            while (i < num_lines && !found)
            {
                std::string next_str = user_input.GetStringAtIndex (i);
                const char *next_line = next_str.c_str();
                if (next_line[0] != ' ' && next_line[0] != '\t')
                    found = true;
                else
                    ++i;
            }
            if (found)
                --i;  // Make 'i' correspond to the last line of the function.
            int function_end = i;

            // Special case:  All of user_input is one big function definition.
            if ((function_start == 0) && (function_end == (num_lines - 1)))
            {
                ExportFunctionDefinitionToInterpreter (user_input);
                last_function_call = func_name + " ()";
                callback_data.AppendString (last_function_call.c_str());
                return callback_data.GetSize() > 0;
            }
            else
              {
                // Make a copy of the function definition:
                StringList new_function;
                for (int k = function_start; k <= function_end; ++k)
                {
                    new_function.AppendString (user_input.GetStringAtIndex (k));
                    // Mark the string to be deleted from user_input.
                    user_input.DeleteStringAtIndex (k);
                    user_input.InsertStringAtIndex (k, "<lldb_delete>");
                }
                ExportFunctionDefinitionToInterpreter (new_function);
                last_function_call = func_name + " ()";
            }
        }
    }

    // Now instead of trying to really delete the marked lines from user_input, we will just copy all the
    // unmarked lines into a new StringList.

    StringList new_user_input;

    for (int i = 0; i < num_lines; ++i)
    {
        std::string current_string = user_input.GetStringAtIndex (i);
        if (current_string.compare (0, 13, "<lldb_delete>") == 0)
            continue;

        new_user_input.AppendString (current_string.c_str());
    }

    num_lines = new_user_input.GetSize();

    if (num_lines > 0)
    {
        if (num_lines == 1
            && strchr (new_user_input.GetStringAtIndex(0), '\n') == NULL)
        {
            // If there's only one line of input, and it doesn't contain any newline characters....
            callback_data.AppendString (new_user_input.GetStringAtIndex (0));
        }
        else
        {
            // Create the new function name.
            StreamString func_name;
            func_name.Printf ("lldb_bp_callback_func_%d", num_created_functions);
            //std::string func_name = "lldb_bp_callback_func_" + num_created_functions;
            ++num_created_functions;

            // Create the function call for the new function.
            last_function_call = func_name.GetString() + " ()";

            // Create the Python function definition line (which will have to be inserted at the beginning of
            // the function).
            std::string def_line = "def " + func_name.GetString() + " ():";


            // Indent all lines an additional four spaces (as they are now being put inside a function definition).
            for (int i = 0; i < num_lines; ++i)
              {
                const char *temp_cstring = new_user_input.GetStringAtIndex(i);
                std::string temp2 = "    ";
                temp2.append(temp_cstring);
                new_user_input.DeleteStringAtIndex (i);
                new_user_input.InsertStringAtIndex (i, temp2.c_str());
              }

            // Insert the function definition line at the top of the new function.
            new_user_input.InsertStringAtIndex (0, def_line.c_str());

            ExportFunctionDefinitionToInterpreter (new_user_input);
            callback_data.AppendString (last_function_call.c_str());
        }
    }
    else
    {
        if (!last_function_call.empty())
          callback_data.AppendString (last_function_call.c_str());
    }

    return callback_data.GetSize() > 0;
}

bool
ScriptInterpreterPython::BreakpointCallbackFunction 
(
    void *baton, 
    StoppointCallbackContext *context,
    lldb::user_id_t break_id, 
    lldb::user_id_t break_loc_id
)
{
    bool ret_value = true;
    bool temp_bool;

    BreakpointOptions::CommandData *bp_option_data =  (BreakpointOptions::CommandData *) baton;

    const char *python_string = bp_option_data->script_source.GetStringAtIndex(0);

    if (python_string != NULL)
    {
        bool success =
          Debugger::GetSharedInstance().GetCommandInterpreter().GetScriptInterpreter()->ExecuteOneLineWithReturn
                                                                                            (python_string,
                                                                                             ScriptInterpreter::eBool,
                                                                                             (void *) &temp_bool);
        if (success)
          ret_value = temp_bool;
    }

    return ret_value;
}
