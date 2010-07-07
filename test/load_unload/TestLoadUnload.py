"""
Test that breakpoint by symbol name works correctly dlopen'ing a dynamic lib.
"""

import os, time
import unittest
import lldb
import lldbtest

class TestClassTypes(lldbtest.TestBase):

    mydir = "load_unload"

    def test_dead_strip(self):
        """Test breakpoint by name works correctly with dlopen'ing."""
        res = self.res
        exe = os.path.join(os.getcwd(), "a.out")
        self.ci.HandleCommand("file " + exe, res)
        self.assertTrue(res.Succeeded())

        # Break by function name a_function (not yet loaded).
        self.ci.HandleCommand("breakpoint set -n a_function", res)
        self.assertTrue(res.Succeeded())
        self.assertTrue(res.GetOutput().startswith(
            "Breakpoint created: 1: name = 'a_function', locations = 0 "
            "(pending)"
            ))

        self.ci.HandleCommand("run", res)
        time.sleep(0.1)
        self.assertTrue(res.Succeeded())

        # The stop reason of the thread should be breakpoint and at a_function.
        self.ci.HandleCommand("thread list", res)
        output = res.GetOutput()
        self.assertTrue(res.Succeeded())
        self.assertTrue(output.find('state is Stopped') > 0 and
                        output.find('a_function') > 0 and
                        output.find('a.c:14') > 0 and
                        output.find('stop reason = breakpoint') > 0)

        # The breakpoint should have a hit count of 1.
        self.ci.HandleCommand("breakpoint list", res)
        self.assertTrue(res.Succeeded())
        self.assertTrue(res.GetOutput().find(' resolved, hit count = 1') > 0)

        self.ci.HandleCommand("continue", res)
        self.assertTrue(res.Succeeded())

#         # We should stop agaian at a_function.
#         # The stop reason of the thread should be breakpoint and at a_function.
#         self.ci.HandleCommand("thread list", res)
#         output = res.GetOutput()
#         self.assertTrue(res.Succeeded())
#         self.assertTrue(output.find('state is Stopped') > 0 and
#                         output.find('a_function') > 0 and
#                         output.find('a.c:14') > 0 and
#                         output.find('stop reason = breakpoint') > 0)

#         # The breakpoint should have a hit count of 2.
#         self.ci.HandleCommand("breakpoint list", res)
#         self.assertTrue(res.Succeeded())
#         self.assertTrue(res.GetOutput().find(' resolved, hit count = 2') > 0)

#         self.ci.HandleCommand("continue", res)
#         self.assertTrue(res.Succeeded())


if __name__ == '__main__':
    lldb.SBDebugger.Initialize()
    unittest.main()
    lldb.SBDebugger.Terminate()
