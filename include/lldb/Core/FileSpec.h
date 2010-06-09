//===-- FileSpec.h ----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_FileSpec_h_
#define liblldb_FileSpec_h_
#if defined(__cplusplus)

#include "lldb/lldb-private.h"
#include "lldb/Core/ConstString.h"
#include "lldb/Core/STLUtils.h"
#include "lldb/Host/TimeValue.h"

namespace lldb_private {

//----------------------------------------------------------------------
/// @class FileSpec FileSpec.h "lldb/Core/FileSpec.h"
/// @brief A file utility class.
///
/// A file specification class that divides paths up into a directory
/// and filename. These string values of the paths are put into uniqued
/// string pools for fast comparisons and efficient memory usage.
//----------------------------------------------------------------------
class FileSpec
{
public:
    typedef enum FileType
    {
        eFileTypeInvalid = -1,
        eFileTypeUknown = 0,
        eFileTypeDirectory,
        eFileTypePipe,
        eFileTypeRegular,
        eFileTypeSocket,
        eFileTypeSymbolicLink
    } FileType;

    FileSpec();

    //------------------------------------------------------------------
    /// Default constructor.
    ///
    /// Takes an optional full path to a file. If \a path is valid,
    /// this function will call FileSpec::SetFile (\a path).
    ///
    /// @param[in] path
    ///     The full or partial path to a file.
    ///
    /// @see FileSpec::SetFile ()
    //------------------------------------------------------------------
    explicit FileSpec (const char *path);

    //------------------------------------------------------------------
    /// Copy constructor
    ///
    /// Makes a copy of the uniqued directory and filename strings from
    /// \a rhs.
    ///
    /// @param[in] rhs
    ///     A const FileSpec object reference to copy.
    //------------------------------------------------------------------
    FileSpec (const FileSpec& rhs);

    //------------------------------------------------------------------
    /// Copy constructor
    ///
    /// Makes a copy of the uniqued directory and filename strings from
    /// \a rhs if it is not NULL.
    ///
    /// @param[in] rhs
    ///     A const FileSpec object pointer to copy if non-NULL.
    //------------------------------------------------------------------
    FileSpec (const FileSpec* rhs);

    //------------------------------------------------------------------
    /// Destructor.
    ///
    /// The destructor is virtual in case this class is subclassed.
    //------------------------------------------------------------------
    virtual
    ~FileSpec ();

    //------------------------------------------------------------------
    /// Assignment operator.
    ///
    /// Makes a copy of the uniqued directory and filename strings from
    /// \a rhs.
    ///
    /// @param[in] rhs
    ///     A const FileSpec object reference to assign to this object.
    ///
    /// @return
    ///     A const reference to this object.
    //------------------------------------------------------------------
    const FileSpec&
    operator= (const FileSpec& rhs);

    //------------------------------------------------------------------
    /// Equal to operator
    ///
    /// Tests if this object is equal to \a rhs.
    ///
    /// @param[in] rhs
    ///     A const FileSpec object reference to compare this object
    ///     to.
    ///
    /// @return
    ///     \b true if this object is equal to \a rhs, \b false
    ///     otherwise.
    //------------------------------------------------------------------
    bool
    operator== (const FileSpec& rhs) const;

    //------------------------------------------------------------------
    /// Not equal to operator
    ///
    /// Tests if this object is not equal to \a rhs.
    ///
    /// @param[in] rhs
    ///     A const FileSpec object reference to compare this object
    ///     to.
    ///
    /// @return
    ///     \b true if this object is equal to \a rhs, \b false
    ///     otherwise.
    //------------------------------------------------------------------
    bool
    operator!= (const FileSpec& rhs) const;

    //------------------------------------------------------------------
    /// Less than to operator
    ///
    /// Tests if this object is less than \a rhs.
    ///
    /// @param[in] rhs
    ///     A const FileSpec object reference to compare this object
    ///     to.
    ///
    /// @return
    ///     \b true if this object is less than \a rhs, \b false
    ///     otherwise.
    //------------------------------------------------------------------
    bool
    operator< (const FileSpec& rhs) const;

    //------------------------------------------------------------------
    /// Convert to pointer operator.
    ///
    /// This allows code to check a FileSpec object to see if it
    /// contains anything valid using code such as:
    ///
    /// @code
    /// FileSpec file_spec(...);
    /// if (file_spec)
    /// { ...
    /// @endcode
    ///
    /// @return
    ///     A pointer to this object if either the directory or filename
    ///     is valid, NULL otherwise.
    //------------------------------------------------------------------
    operator
    void* () const;

    //------------------------------------------------------------------
    /// Logical NOT operator.
    ///
    /// This allows code to check a FileSpec object to see if it is
    /// invalid using code such as:
    ///
    /// @code
    /// FileSpec file_spec(...);
    /// if (!file_spec)
    /// { ...
    /// @endcode
    ///
    /// @return
    ///     Returns \b true if the object has an empty directory and
    ///     filename, \b false otherwise.
    //------------------------------------------------------------------
    bool
    operator! () const;

    //------------------------------------------------------------------
    /// Clears the object state.
    ///
    /// Clear this object by releasing both the directory and filename
    /// string values and reverting them to empty strings.
    //------------------------------------------------------------------
    void
    Clear ();

    //------------------------------------------------------------------
    /// Compare two FileSpec objects.
    ///
    /// If \a full is true, then both the directory and the filename
    /// must match. If \a full is false, then the directory names for
    /// \a lhs and \a rhs are only compared if they are both not empty.
    /// This allows a FileSpec object to only contain a filename
    /// and it can match FileSpec objects that have matching
    /// filenames with different paths.
    ///
    /// @param[in] lhs
    ///     A const reference to the Left Hand Side object to compare.
    ///
    /// @param[in] rhs
    ///     A const reference to the Right Hand Side object to compare.
    ///
    /// @param[in] full
    ///     If true, then both the directory and filenames will have to
    ///     match for a compare to return zero (equal to). If false
    ///     and either directory from \a lhs or \a rhs is empty, then
    ///     only the filename will be compared, else a full comparison
    ///     is done.
    ///
    /// @return
    ///     @li -1 if \a lhs is less than \a rhs
    ///     @li 0 if \a lhs is equal to \a rhs
    ///     @li 1 if \a lhs is greater than \a rhs
    //------------------------------------------------------------------
    static int
    Compare (const FileSpec& lhs, const FileSpec& rhs, bool full);

    static bool
    Equal (const FileSpec& a, const FileSpec& b, bool full);

    //------------------------------------------------------------------
    /// Dump this object to a Stream.
    ///
    /// Dump the object to the supplied stream \a s. If the object
    /// contains a valid directory name, it will be displayed followed
    /// by a directory delimiter, and the filename.
    ///
    /// @param[in] s
    ///     The stream to which to dump the object descripton.
    //------------------------------------------------------------------
    void
    Dump (Stream *s) const;

    //------------------------------------------------------------------
    /// Existence test.
    ///
    /// @return
    ///     \b true if the file exists on disk, \b false otherwise.
    //------------------------------------------------------------------
    bool
    Exists () const;

    uint64_t
    GetByteSize() const;

    //------------------------------------------------------------------
    /// Directory string get accessor.
    ///
    /// @return
    ///     A reference to the directory string object.
    //------------------------------------------------------------------
    ConstString &
    GetDirectory ();

    //------------------------------------------------------------------
    /// Directory string const get accessor.
    ///
    /// @return
    ///     A const reference to the directory string object.
    //------------------------------------------------------------------
    const ConstString &
    GetDirectory () const;

    //------------------------------------------------------------------
    /// Filename string get accessor.
    ///
    /// @return
    ///     A reference to the filename string object.
    //------------------------------------------------------------------
    ConstString &
    GetFilename ();

    //------------------------------------------------------------------
    /// Filename string const get accessor.
    ///
    /// @return
    ///     A const reference to the filename string object.
    //------------------------------------------------------------------
    const ConstString &
    GetFilename () const;

    TimeValue
    GetModificationTime () const;

    //------------------------------------------------------------------
    /// Extract the full path to the file.
    ///
    /// Extract the directory and path into a fixed buffer. This is
    /// needed as the directory and path are stored in separate string
    /// values.
    ///
    /// @param[out] path
    ///     The buffer in which to place the extracted full path.
    ///
    /// @param[in] max_path_length
    ///     The maximum length or \a path.
    ///
    /// @return
    ///     \b true if the extracted fullpath fits into \a path, \b
    ///     false otherwise.
    //------------------------------------------------------------------
    bool
    GetPath (char *path, size_t max_path_length) const;

    FileType
    GetFileType () const;

    //------------------------------------------------------------------
    /// Get the memory cost of this object.
    ///
    /// Return the size in bytes that this object takes in memory. This
    /// returns the size in bytes of this object, not any shared string
    /// values it may refer to.
    ///
    /// @return
    ///     The number of bytes that this object occupies in memory.
    ///
    /// @see ConstString::StaticMemorySize ()
    //------------------------------------------------------------------
    size_t
    MemorySize () const;

    //------------------------------------------------------------------
    /// Memory map part of, or the entire contents of, a file.
    ///
    /// Returns a shared pointer to a data buffer that contains all or
    /// part of the contents of a file. The data is memory mapped and
    /// will lazily page in data from the file as memory is accessed.
    /// The data that is mappped will start \a offset bytes into the
    /// file, and \a length bytes will be mapped. If \a length is
    /// greater than the number of bytes available in the file starting
    /// at \a offset, the number of bytes will be appropriately
    /// truncated. The final number of bytes that get mapped can be
    /// verified using the DataBuffer::GetByteSize() function on the return
    /// shared data pointer object contents.
    ///
    /// @param[in] offset
    ///     The offset in bytes from the beginning of the file where
    ///     memory mapping should begin.
    ///
    /// @param[in] length
    ///     The size in bytes that should be mapped starting \a offset
    ///     bytes into the file. If \a length is \c SIZE_MAX, map
    ///     as many bytes as possible.
    ///
    /// @return
    ///     A shared pointer to the memeory mapped data. This shared
    ///     pointer can contain a NULL DataBuffer pointer, so the contained
    ///     pointer must be checked prior to using it.
    //------------------------------------------------------------------
    lldb::DataBufferSP
    MemoryMapFileContents (off_t offset = 0, size_t length = SIZE_MAX) const;

    //------------------------------------------------------------------
    /// Read part of, or the entire contents of, a file into a heap based data buffer.
    ///
    /// Returns a shared pointer to a data buffer that contains all or
    /// part of the contents of a file. The data copies into a heap based
    /// buffer that lives in the DataBuffer shared pointer object returned.
    /// The data that is cached will start \a offset bytes into the
    /// file, and \a length bytes will be mapped. If \a length is
    /// greater than the number of bytes available in the file starting
    /// at \a offset, the number of bytes will be appropriately
    /// truncated. The final number of bytes that get mapped can be
    /// verified using the DataBuffer::GetByteSize() function.
    ///
    /// @param[in] offset
    ///     The offset in bytes from the beginning of the file where
    ///     memory mapping should begin.
    ///
    /// @param[in] length
    ///     The size in bytes that should be mapped starting \a offset
    ///     bytes into the file. If \a length is \c SIZE_MAX, map
    ///     as many bytes as possible.
    ///
    /// @return
    ///     A shared pointer to the memeory mapped data. This shared
    ///     pointer can contain a NULL DataBuffer pointer, so the contained
    ///     pointer must be checked prior to using it.
    //------------------------------------------------------------------
    lldb::DataBufferSP
    ReadFileContents (off_t offset = 0, size_t length = SIZE_MAX) const;

    //------------------------------------------------------------------
    /// Change the file specificed with a new path.
    ///
    /// Update the contents of this object with a new path. The path will
    /// be split up into a directory and filename and stored as uniqued
    /// string values for quick comparison and efficient memory usage.
    ///
    /// @param[in] path
    ///     A full, partial, or relative path to a file.
    //------------------------------------------------------------------
    void
    SetFile (const char *path);

    //------------------------------------------------------------------
    /// Read the file into an array of strings, one per line.
    ///
    /// Opens and reads the file in this object into an array of strings,
    /// one string per line of the file. Returns a boolean indicating
    /// success or failure.
    ///
    /// @param[out] lines
    ///     The string array into which to read the file.
    //------------------------------------------------------------------
    bool
    ReadFileLines (STLStringArray &lines);

    static int
    Resolve (const char *src_path, char *dst_path, size_t dst_len);

protected:
    //------------------------------------------------------------------
    // Member variables
    //------------------------------------------------------------------
    ConstString m_directory;    ///< The uniqued directory path
    ConstString m_filename;     ///< The uniqued filename path
};

//----------------------------------------------------------------------
/// Dump a FileSpec object to a stream
//----------------------------------------------------------------------
Stream& operator << (Stream& s, const FileSpec& f);

} // namespace lldb_private

#endif  // #if defined(__cplusplus)
#endif  // liblldb_FileSpec_h_
