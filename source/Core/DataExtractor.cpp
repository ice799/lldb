//===-- DataExtractor.cpp ---------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <assert.h>
#include <stddef.h>

#include <bitset>
#include <string>

#include "llvm/Support/MathExtras.h"

#include "lldb/Core/DataExtractor.h"
#include "lldb/Core/DataBuffer.h"
#include "lldb/Core/Log.h"
#include "lldb/Core/Stream.h"
#include "lldb/Core/StreamString.h"
#include "lldb/Core/UUID.h"
#include "lldb/Core/dwarf.h"

using namespace lldb;
using namespace lldb_private;

static inline uint16_t 
ReadInt16(const unsigned char* ptr, unsigned offset) 
{
    return *(uint16_t *)(ptr + offset);
}
static inline uint32_t
ReadInt32 (const unsigned char* ptr, unsigned offset) 
{
    return *(uint32_t *)(ptr + offset);
}

static inline uint64_t 
ReadInt64(const unsigned char* ptr, unsigned offset) 
{
    return *(uint64_t *)(ptr + offset);
}

static inline uint16_t
ReadSwapInt16(const unsigned char* ptr, unsigned offset) 
{
    return llvm::ByteSwap_16(*(uint16_t *)(ptr + offset));
}

static inline uint32_t
ReadSwapInt32 (const unsigned char* ptr, unsigned offset) 
{
    return llvm::ByteSwap_32(*(uint32_t *)(ptr + offset));
}
static inline uint64_t 
ReadSwapInt64(const unsigned char* ptr, unsigned offset) 
{
  return llvm::ByteSwap_64(*(uint64_t *)(ptr + offset));
}

#define NON_PRINTABLE_CHAR '.'
//----------------------------------------------------------------------
// Default constructor.
//----------------------------------------------------------------------
DataExtractor::DataExtractor () :
    m_start     (NULL),
    m_end       (NULL),
    m_byte_order(eByteOrderHost),
    m_addr_size (4),
    m_data_sp   ()
{
}

//----------------------------------------------------------------------
// This constructor allows us to use data that is owned by someone else.
// The data must stay around as long as this object is valid.
//----------------------------------------------------------------------
DataExtractor::DataExtractor (const void* data, uint32_t length, ByteOrder endian, uint8_t addr_size) :
    m_start     ((uint8_t*)data),
    m_end       ((uint8_t*)data + length),
    m_byte_order(endian),
    m_addr_size (addr_size),
    m_data_sp   ()
{
}

//----------------------------------------------------------------------
// Make a shared pointer reference to the shared data in "data_sp" and
// set the endian swapping setting to "swap", and the address size to
// "addr_size". The shared data reference will ensure the data lives
// as long as any DataExtractor objects exist that have a reference to
// this data.
//----------------------------------------------------------------------
DataExtractor::DataExtractor (DataBufferSP& data_sp, ByteOrder endian, uint8_t addr_size) :
    m_start     (NULL),
    m_end       (NULL),
    m_byte_order(endian),
    m_addr_size (addr_size),
    m_data_sp   ()
{
    SetData (data_sp);
}

//----------------------------------------------------------------------
// Initialize this object with a subset of the data bytes in "data".
// If "data" contains shared data, then a reference to this shared
// data will added and the shared data will stay around as long
// as any object contains a reference to that data. The endian
// swap and address size settings are copied from "data".
//----------------------------------------------------------------------
DataExtractor::DataExtractor (const DataExtractor& data, uint32_t offset, uint32_t length) :
    m_start(NULL),
    m_end(NULL),
    m_byte_order(data.m_byte_order),
    m_addr_size(data.m_addr_size),
    m_data_sp()
{
    if (data.ValidOffset(offset))
    {
        uint32_t bytes_available = data.GetByteSize() - offset;
        if (length > bytes_available)
            length = bytes_available;
        SetData(data, offset, length);
    }
}

//----------------------------------------------------------------------
// Assignment operator
//----------------------------------------------------------------------
const DataExtractor&
DataExtractor::operator= (const DataExtractor& rhs)
{
    if (this != &rhs)
    {
        m_start     = rhs.m_start;
        m_end       = rhs.m_end;
        m_byte_order= rhs.m_byte_order;
        m_addr_size = rhs.m_addr_size;
        m_data_sp   = rhs.m_data_sp;
    }
    return *this;
}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
DataExtractor::~DataExtractor ()
{
}

//------------------------------------------------------------------
// Clears the object contents back to a default invalid state, and
// release any references to shared data that this object may
// contain.
//------------------------------------------------------------------
void
DataExtractor::Clear ()
{
    m_start = NULL;
    m_end = NULL;
    m_byte_order = eByteOrderHost;
    m_addr_size = 4;
    m_data_sp.reset();
}

//------------------------------------------------------------------
// Returns the total number of bytes that this object refers to
//------------------------------------------------------------------
size_t
DataExtractor::GetByteSize () const
{
    return m_end - m_start;
}

//------------------------------------------------------------------
// If this object contains shared data, this function returns the
// offset into that shared data. Else zero is returned.
//------------------------------------------------------------------
size_t
DataExtractor::GetSharedDataOffset () const
{
    if (m_start != NULL)
    {
        const DataBuffer * data = m_data_sp.get();
        if (data != NULL)
        {
            const uint8_t * data_bytes = data->GetBytes();
            if (data_bytes != NULL)
            {
                assert(m_start >= data_bytes);
                return m_start - data_bytes;
            }
        }
    }
    return 0;
}

//------------------------------------------------------------------
// Returns true if OFFSET is a valid offset into the data in this
// object.
//------------------------------------------------------------------
bool
DataExtractor::ValidOffset (uint32_t offset) const
{
    return offset < GetByteSize();
}

//------------------------------------------------------------------
// Returns true if there are LENGTH bytes availabe starting OFFSET
// into the data that is in this object.
//------------------------------------------------------------------
bool
DataExtractor::ValidOffsetForDataOfSize (uint32_t offset, uint32_t length) const
{
    size_t size = GetByteSize();
    if (offset >= size)
        return false;   // offset isn't valid

    if (length == 0)
        return true;    // No bytes requested at this offset, return true

    // If we flip the bits in offset we can figure out how
    // many bytes we have left before "offset + length"
    // could overflow when doing unsigned arithmetic.
    if (length > ~offset)
        return false;   // unsigned overflow

    // Make sure "offset + length" is a valid offset as well.
    // length must be greater than zero for this to be a
    // valid expression, and we have already checked for this.
    return ((offset + length) <= size);
}

//------------------------------------------------------------------
// Returns a pointer to the first byte contained in this object's
// data, or NULL of there is no data in this object.
//------------------------------------------------------------------
const uint8_t *
DataExtractor::GetDataStart () const
{
    return m_start;
}
//------------------------------------------------------------------
// Returns a pointer to the byte past the last byte contained in
// this object's data, or NULL of there is no data in this object.
//------------------------------------------------------------------
const uint8_t *
DataExtractor::GetDataEnd () const
{
    return m_end;
}

//------------------------------------------------------------------
// Returns true if this object will endian swap values as it
// extracts data.
//------------------------------------------------------------------
ByteOrder
DataExtractor::GetByteOrder () const
{
    return m_byte_order;
}
//------------------------------------------------------------------
// Set wether this object will endian swap values as it extracts
// data.
//------------------------------------------------------------------
void
DataExtractor::SetByteOrder (ByteOrder endian)
{
    m_byte_order = endian;
}


//------------------------------------------------------------------
// Return the size in bytes of any address values this object will
// extract
//------------------------------------------------------------------
uint8_t
DataExtractor::GetAddressByteSize () const
{
    return m_addr_size;
}

//------------------------------------------------------------------
// Set the size in bytes that will be used when extracting any
// address values from data contained in this object.
//------------------------------------------------------------------
void
DataExtractor::SetAddressByteSize (uint8_t addr_size)
{
    m_addr_size = addr_size;
}

//----------------------------------------------------------------------
// Set the data with which this object will extract from to data
// starting at BYTES and set the length of the data to LENGTH bytes
// long. The data is externally owned must be around at least as
// long as this object points to the data. No copy of the data is
// made, this object just refers to this data and can extract from
// it. If this object refers to any shared data upon entry, the
// reference to that data will be released. Is SWAP is set to true,
// any data extracted will be endian swapped.
//----------------------------------------------------------------------
uint32_t
DataExtractor::SetData (const void *bytes, uint32_t length, ByteOrder endian)
{
    m_byte_order = endian;
    m_data_sp.reset();
    if (bytes == NULL || length == 0)
    {
        m_start = NULL;
        m_end = NULL;
    }
    else
    {
        m_start = (uint8_t *)bytes;
        m_end = m_start + length;
    }
    return GetByteSize();
}

//----------------------------------------------------------------------
// Assign the data for this object to be a subrange in "data"
// starting "data_offset" bytes into "data" and ending "data_length"
// bytes later. If "data_offset" is not a valid offset into "data",
// then this object will contain no bytes. If "data_offset" is
// within "data" yet "data_length" is too large, the length will be
// capped at the number of bytes remaining in "data". If "data"
// contains a shared pointer to other data, then a ref counted
// pointer to that data will be made in this object. If "data"
// doesn't contain a shared pointer to data, then the bytes referred
// to in "data" will need to exist at least as long as this object
// refers to those bytes. The address size and endian swap settings
// are copied from the current values in "data".
//----------------------------------------------------------------------
uint32_t
DataExtractor::SetData (const DataExtractor& data, uint32_t data_offset, uint32_t data_length)
{
    m_addr_size = data.m_addr_size;
    // If "data" contains shared pointer to data, then we can use that
    if (data.m_data_sp.get())
    {
        m_byte_order = data.m_byte_order;
        return SetData(data.m_data_sp, data.GetSharedDataOffset() + data_offset, data_length);
    }

    // We have a DataExtractor object that just has a pointer to bytes
    if (data.ValidOffset(data_offset))
    {
        if (data_length > data.GetByteSize() - data_offset)
            data_length = data.GetByteSize() - data_offset;
        return SetData (data.GetDataStart() + data_offset, data_length, data.GetByteOrder());
    }
    return 0;
}

//----------------------------------------------------------------------
// Assign the data for this object to be a subrange of the shared
// data in "data_sp" starting "data_offset" bytes into "data_sp"
// and ending "data_length" bytes later. If "data_offset" is not
// a valid offset into "data_sp", then this object will contain no
// bytes. If "data_offset" is within "data_sp" yet "data_length" is
// too large, the length will be capped at the number of bytes
// remaining in "data_sp". A ref counted pointer to the data in
// "data_sp" will be made in this object IF the number of bytes this
// object refers to in greater than zero (if at least one byte was
// available starting at "data_offset") to ensure the data stays
// around as long as it is needed. The address size and endian swap
// settings will remain unchanged from their current settings.
//----------------------------------------------------------------------
uint32_t
DataExtractor::SetData (DataBufferSP& data_sp, uint32_t data_offset, uint32_t data_length)
{
    m_start = m_end = NULL;

    if (data_length > 0)
    {
        m_data_sp = data_sp;
        if (data_sp.get())
        {
            const size_t data_size = data_sp->GetByteSize();
            if (data_offset < data_size)
            {
                m_start = data_sp->GetBytes() + data_offset;
                const size_t bytes_left = data_size - data_offset;
                // Cap the length of we asked for too many
                if (data_length <= bytes_left)
                    m_end = m_start + data_length;  // We got all the bytes we wanted
                else
                    m_end = m_start + bytes_left;   // Not all the bytes requested were available in the shared data
            }
        }
    }

    uint32_t new_size = GetByteSize();

    // Don't hold a shared pointer to the data buffer if we don't share
    // any valid bytes in the shared buffer.
    if (new_size == 0)
        m_data_sp.reset();

    return new_size;
}

//----------------------------------------------------------------------
// Extract a single unsigned char from the binary data and update
// the offset pointed to by "offset_ptr".
//
// RETURNS the byte that was extracted, or zero on failure.
//----------------------------------------------------------------------
uint8_t
DataExtractor::GetU8 (uint32_t *offset_ptr) const
{
    uint8_t val = 0;
    if ( m_start < m_end )
    {
        val = m_start[*offset_ptr];
        *offset_ptr += sizeof(val);
    }
    return val;
}

//----------------------------------------------------------------------
// Extract "count" unsigned chars from the binary data and update the
// offset pointed to by "offset_ptr". The extracted data is copied into
// "dst".
//
// RETURNS the non-NULL buffer pointer upon successful extraction of
// all the requested bytes, or NULL when the data is not available in
// the buffer due to being out of bounds, or unsufficient data.
//----------------------------------------------------------------------
void *
DataExtractor::GetU8 (uint32_t *offset_ptr, void *dst, uint32_t count) const
{
    register uint32_t offset = *offset_ptr;

    if ((count > 0) && ValidOffsetForDataOfSize(offset, count) )
    {
        // Copy the data into the buffer
        memcpy (dst, m_start + offset, count);
        // Advance the offset
        *offset_ptr += count;
        // Return a non-NULL pointer to the converted data as an indicator of success
        return dst;
    }
    return NULL;
}

//----------------------------------------------------------------------
// Extract a single uint16_t from the data and update the offset
// pointed to by "offset_ptr".
//
// RETURNS the uint16_t that was extracted, or zero on failure.
//----------------------------------------------------------------------
uint16_t
DataExtractor::GetU16 (uint32_t *offset_ptr) const
{
    uint16_t val = 0;
    register uint32_t offset = *offset_ptr;
    if ( ValidOffsetForDataOfSize(offset, sizeof(val)) )
    {
        if (m_byte_order != eByteOrderHost)
            val = ReadSwapInt16(m_start, offset);
        else
            val = ReadInt16 (m_start, offset);

        // Advance the offset
        *offset_ptr += sizeof(val);
    }
    return val;
}

//----------------------------------------------------------------------
// Extract "count" uint16_t values from the binary data and update
// the offset pointed to by "offset_ptr". The extracted data is
// copied into "dst".
//
// RETURNS the non-NULL buffer pointer upon successful extraction of
// all the requested bytes, or NULL when the data is not available
// in the buffer due to being out of bounds, or unsufficient data.
//----------------------------------------------------------------------
void *
DataExtractor::GetU16 (uint32_t *offset_ptr, void *void_dst, uint32_t count) const
{
    uint16_t *dst = (uint16_t *)void_dst;
    const size_t value_size = sizeof(*dst);
    register uint32_t offset = *offset_ptr;

    if ((count > 0) && ValidOffsetForDataOfSize(offset, value_size * count) )
    {
        uint16_t *value_ptr;
        uint16_t *end = dst + count;
        if (m_byte_order != eByteOrderHost)
        {
            for (value_ptr = dst; value_ptr < end; ++value_ptr, offset += value_size)
                *value_ptr = ReadSwapInt16 (m_start, offset);
        }
        else
        {
            for (value_ptr = dst; value_ptr < end; ++value_ptr, offset += value_size)
                *value_ptr = ReadInt16 (m_start, offset);
        }

        // Advance the offset
        *offset_ptr = offset;
        // Return a non-NULL pointer to the converted data as an indicator of success
        return dst;
    }
    return NULL;
}

//----------------------------------------------------------------------
// Extract a single uint32_t from the data and update the offset
// pointed to by "offset_ptr".
//
// RETURNS the uint32_t that was extracted, or zero on failure.
//----------------------------------------------------------------------
uint32_t
DataExtractor::GetU32 (uint32_t *offset_ptr) const
{
    uint32_t val = 0;
    register uint32_t offset = *offset_ptr;

    if ( ValidOffsetForDataOfSize(offset, sizeof(val)) )
    {
        if (m_byte_order != eByteOrderHost)
            val = ReadSwapInt32 (m_start, offset);
        else
            val = ReadInt32 (m_start, offset);

        // Advance the offset
        *offset_ptr += sizeof(val);
    }
    return val;
}

//----------------------------------------------------------------------
// Extract "count" uint32_t values from the binary data and update
// the offset pointed to by "offset_ptr". The extracted data is
// copied into "dst".
//
// RETURNS the non-NULL buffer pointer upon successful extraction of
// all the requested bytes, or NULL when the data is not available
// in the buffer due to being out of bounds, or unsufficient data.
//----------------------------------------------------------------------
void *
DataExtractor::GetU32 (uint32_t *offset_ptr, void *void_dst, uint32_t count) const
{
    uint32_t *dst = (uint32_t *)void_dst;
    const size_t value_size = sizeof(*dst);
    register uint32_t offset = *offset_ptr;

    if ((count > 0) && ValidOffsetForDataOfSize(offset, value_size * count))
    {
        uint32_t *value_ptr;
        uint32_t *end = dst + count;
        if (m_byte_order != eByteOrderHost)
        {
            for (value_ptr = dst; value_ptr < end; ++value_ptr, offset += value_size)
                *value_ptr = ReadSwapInt32 (m_start, offset);

        }
        else
        {
            for (value_ptr = dst; value_ptr < end; ++value_ptr, offset += value_size)
                *value_ptr = ReadInt32 (m_start, offset);
        }

        // Advance the offset
        *offset_ptr = offset;
        // Return a non-NULL pointer to the converted data as an indicator of success
        return dst;
    }
    return NULL;
}

//----------------------------------------------------------------------
// Extract a single uint64_t from the data and update the offset
// pointed to by "offset_ptr".
//
// RETURNS the uint64_t that was extracted, or zero on failure.
//----------------------------------------------------------------------
uint64_t
DataExtractor::GetU64 (uint32_t *offset_ptr) const
{
    uint64_t val = 0;
    register uint32_t offset = *offset_ptr;
    if ( ValidOffsetForDataOfSize(offset, sizeof(val)) )
    {
        if (m_byte_order != eByteOrderHost)
            val = ReadSwapInt64 (m_start, offset);
        else
            val = ReadInt64 (m_start, offset);

        // Advance the offset
        *offset_ptr += sizeof(val);
    }
    return val;
}

//----------------------------------------------------------------------
// GetU64
//
// Get multiple consecutive 64 bit values. Return true if the entire
// read succeeds and increment the offset pointed to by offset_ptr, else
// return false and leave the offset pointed to by offset_ptr unchanged.
//----------------------------------------------------------------------
void *
DataExtractor::GetU64 (uint32_t *offset_ptr, void *void_dst, uint32_t count) const
{
    uint64_t *dst = (uint64_t *)void_dst;
    const size_t value_size = sizeof(uint64_t);
    register uint32_t offset = *offset_ptr;

    if ((count > 0) && ValidOffsetForDataOfSize(offset, value_size * count))
    {
        uint64_t *value_ptr;
        uint64_t *end = dst + count;
        if (m_byte_order != eByteOrderHost)
        {
            for (value_ptr = dst; value_ptr < end; ++value_ptr, offset += value_size)
                *value_ptr = ReadSwapInt64 (m_start, offset);

        }
        else
        {
            for (value_ptr = dst; value_ptr < end; ++value_ptr, offset += value_size)
                *value_ptr = ReadInt64 (m_start, offset);
        }

        // Advance the offset
        *offset_ptr = offset;
        // Return a non-NULL pointer to the converted data as an indicator of success
        return dst;
    }
    return NULL;
}

//----------------------------------------------------------------------
// Extract a single integer value from the data and update the offset
// pointed to by "offset_ptr". The size of the extracted integer
// is specified by the "byte_size" argument. "byte_size" should have
// a value between 1 and 4 since the return value is only 32 bits
// wide. Any "byte_size" values less than 1 or greater than 4 will
// result in nothing being extracted, and zero being returned.
//
// RETURNS the integer value that was extracted, or zero on failure.
//----------------------------------------------------------------------
uint32_t
DataExtractor::GetMaxU32 (uint32_t *offset_ptr, uint32_t byte_size) const
{
    switch (byte_size)
    {
    case 1: return GetU8 (offset_ptr); break;
    case 2: return GetU16(offset_ptr); break;
    case 4: return GetU32(offset_ptr); break;
    default:
        assert(!"GetMaxU32 unhandled case!");
        break;
    }
    return 0;
}

//----------------------------------------------------------------------
// Extract a single integer value from the data and update the offset
// pointed to by "offset_ptr". The size of the extracted integer
// is specified by the "byte_size" argument. "byte_size" should have
// a value >= 1 and <= 8 since the return value is only 64 bits
// wide. Any "byte_size" values less than 1 or greater than 8 will
// result in nothing being extracted, and zero being returned.
//
// RETURNS the integer value that was extracted, or zero on failure.
//----------------------------------------------------------------------
uint64_t
DataExtractor::GetMaxU64 (uint32_t *offset_ptr, uint32_t size) const
{
    switch (size)
    {
    case 1: return GetU8 (offset_ptr); break;
    case 2: return GetU16(offset_ptr); break;
    case 4: return GetU32(offset_ptr); break;
    case 8: return GetU64(offset_ptr); break;
    default:
        assert(!"GetMax64 unhandled case!");
        break;
    }
    return 0;
}

int64_t
DataExtractor::GetMaxS64 (uint32_t *offset_ptr, uint32_t size) const
{
    switch (size)
    {
    case 1: return (int8_t)GetU8 (offset_ptr); break;
    case 2: return (int16_t)GetU16(offset_ptr); break;
    case 4: return (int32_t)GetU32(offset_ptr); break;
    case 8: return (int64_t)GetU64(offset_ptr); break;
    default:
        assert(!"GetMax64 unhandled case!");
        break;
    }
    return 0;
}

uint64_t
DataExtractor::GetMaxU64Bitfield (uint32_t *offset_ptr, uint32_t size, uint32_t bitfield_bit_size, uint32_t bitfield_bit_offset) const
{
    uint64_t uval64 = GetMaxU64 (offset_ptr, size);
    if (bitfield_bit_size > 0)
    {
        if (bitfield_bit_offset > 0)
            uval64 >>= bitfield_bit_offset;
        uint64_t bitfield_mask = ((1 << bitfield_bit_size) - 1);
        uval64 &= bitfield_mask;
    }
    return uval64;
}

int64_t
DataExtractor::GetMaxS64Bitfield (uint32_t *offset_ptr, uint32_t size, uint32_t bitfield_bit_size, uint32_t bitfield_bit_offset) const
{
    int64_t sval64 = GetMaxS64 (offset_ptr, size);
    if (bitfield_bit_size > 0)
    {
        if (bitfield_bit_offset > 0)
            sval64 >>= bitfield_bit_offset;
        uint64_t bitfield_mask = ((1 << bitfield_bit_size) - 1);
        sval64 &= bitfield_mask;
        // sign extend if needed
        if (sval64 & (1 << (bitfield_bit_size - 1)))
            sval64 |= ~bitfield_mask;
    }
    return sval64;
}


float
DataExtractor::GetFloat (uint32_t *offset_ptr) const
{
    uint32_t val = 0;
    register uint32_t offset = *offset_ptr;

    if ( ValidOffsetForDataOfSize(offset, sizeof(val)) )
    {
        if (m_byte_order != eByteOrderHost)
            val = ReadSwapInt32 (m_start, offset);
        else
            val = ReadInt32 (m_start, offset);

        // Advance the offset
        *offset_ptr += sizeof(val);
    }
    return *((float *)&val);
}

double
DataExtractor::GetDouble (uint32_t *offset_ptr) const
{
    uint64_t val = 0;
    register uint32_t offset = *offset_ptr;
    if ( ValidOffsetForDataOfSize(offset, sizeof(val)) )
    {
        if (m_byte_order != eByteOrderHost)
            val = ReadSwapInt64 (m_start, offset);
        else
            val = ReadInt64 (m_start, offset);

        // Advance the offset
        *offset_ptr += sizeof(val);
    }
    return *((double *)&val);

}


long double
DataExtractor::GetLongDouble (uint32_t *offset_ptr) const
{
    if (sizeof(long double) == sizeof(uint64_t))
    {
        uint64_t val = 0;
        register uint32_t offset = *offset_ptr;
        if ( ValidOffsetForDataOfSize(offset, sizeof(val)) )
        {
            if (m_byte_order != eByteOrderHost)
                val = ReadSwapInt64 (m_start, offset);
            else
                val = ReadInt64 (m_start, offset);

            // Advance the offset
            *offset_ptr += sizeof(val);
        }
        return *((long double *)&val);
    }
    return 0.0;
}


//------------------------------------------------------------------
// Extract a single address from the data and update the offset
// pointed to by "offset_ptr". The size of the extracted address
// comes from the "this->m_addr_size" member variable and should be
// set correctly prior to extracting any address values.
//
// RETURNS the address that was extracted, or zero on failure.
//------------------------------------------------------------------
uint64_t
DataExtractor::GetAddress (uint32_t *offset_ptr) const
{
    return GetMaxU64 (offset_ptr, m_addr_size);
}

//------------------------------------------------------------------
// Extract a single pointer from the data and update the offset
// pointed to by "offset_ptr". The size of the extracted pointer
// comes from the "this->m_addr_size" member variable and should be
// set correctly prior to extracting any pointer values.
//
// RETURNS the pointer that was extracted, or zero on failure.
//------------------------------------------------------------------
uint64_t
DataExtractor::GetPointer (uint32_t *offset_ptr) const
{
    return GetMaxU64 (offset_ptr, m_addr_size);
}

//----------------------------------------------------------------------
// GetDwarfEHPtr
//
// Used for calls when the value type is specified by a DWARF EH Frame
// pointer encoding.
//----------------------------------------------------------------------

uint64_t
DataExtractor::GetGNUEHPointer (uint32_t *offset_ptr, uint32_t eh_ptr_enc, lldb::addr_t pc_rel_addr, lldb::addr_t text_addr, lldb::addr_t data_addr)//, BSDRelocs *data_relocs) const
{
    if (eh_ptr_enc == DW_EH_PE_omit)
        return ULONG_LONG_MAX;  // Value isn't in the buffer...

    uint64_t baseAddress = 0;
    uint64_t addressValue = 0;
    const uint32_t addr_size = GetAddressByteSize();

    bool signExtendValue = false;
    // Decode the base part or adjust our offset
    switch (eh_ptr_enc & 0x70)
    {
    case DW_EH_PE_pcrel:
        signExtendValue = true;
        baseAddress = *offset_ptr;
        if (pc_rel_addr != LLDB_INVALID_ADDRESS)
            baseAddress += pc_rel_addr;
//      else
//          Log::GlobalWarning ("PC relative pointer encoding found with invalid pc relative address.");
        break;

    case DW_EH_PE_textrel:
        signExtendValue = true;
        if (text_addr != LLDB_INVALID_ADDRESS)
            baseAddress = text_addr;
//      else
//          Log::GlobalWarning ("text relative pointer encoding being decoded with invalid text section address, setting base address to zero.");
        break;

    case DW_EH_PE_datarel:
        signExtendValue = true;
        if (data_addr != LLDB_INVALID_ADDRESS)
            baseAddress = data_addr;
//      else
//          Log::GlobalWarning ("data relative pointer encoding being decoded with invalid data section address, setting base address to zero.");
        break;

    case DW_EH_PE_funcrel:
        signExtendValue = true;
        break;

    case DW_EH_PE_aligned:
        {
            // SetPointerSize should be called prior to extracting these so the
            // pointer size is cached
            assert(addr_size != 0);
            if (addr_size)
            {
                // Align to a address size boundary first
                uint32_t alignOffset = *offset_ptr % addr_size;
                if (alignOffset)
                    offset_ptr += addr_size - alignOffset;
            }
        }
        break;

    default:
    break;
    }

    // Decode the value part
    switch (eh_ptr_enc & DW_EH_PE_MASK_ENCODING)
    {
    case DW_EH_PE_absptr    :
        {
            addressValue = GetAddress (offset_ptr);
//          if (data_relocs)
//              addressValue = data_relocs->Relocate(*offset_ptr - addr_size, *this, addressValue);
        }
        break;
    case DW_EH_PE_uleb128   : addressValue = GetULEB128(offset_ptr);        break;
    case DW_EH_PE_udata2    : addressValue = GetU16(offset_ptr);            break;
    case DW_EH_PE_udata4    : addressValue = GetU32(offset_ptr);            break;
    case DW_EH_PE_udata8    : addressValue = GetU64(offset_ptr);            break;
    case DW_EH_PE_sleb128   : addressValue = GetSLEB128(offset_ptr);        break;
    case DW_EH_PE_sdata2    : addressValue = (int16_t)GetU16(offset_ptr);   break;
    case DW_EH_PE_sdata4    : addressValue = (int32_t)GetU32(offset_ptr);   break;
    case DW_EH_PE_sdata8    : addressValue = (int64_t)GetU64(offset_ptr);   break;
    default:
    // Unhandled encoding type
    assert(eh_ptr_enc);
    break;
    }

    // Since we promote everything to 64 bit, we may need to sign extend
    if (signExtendValue && addr_size < sizeof(baseAddress))
    {
        uint64_t sign_bit = 1ull << ((addr_size * 8ull) - 1ull);
        if (sign_bit & addressValue)
        {
            uint64_t mask = ~sign_bit + 1;
            addressValue |= mask;
        }
    }
    return baseAddress + addressValue;
}

size_t
DataExtractor::ExtractBytes (uint32_t offset, uint32_t length, ByteOrder dst_byte_order, void *dst) const
{
    const uint8_t *src = PeekData (offset, length);
    if (src)
    {
        if (dst_byte_order != GetByteOrder())
        {
            for (uint32_t i=0; i<length; ++i)
                ((uint8_t*)dst)[i] = src[length - i - 1];
        }
        else
            ::memcpy (dst, src, length);
        return length;
    }
    return 0;
}
//----------------------------------------------------------------------
// Peeks at bytes in the contained data.
//
// Returns a valid pointer to bytes if "offset" is a valid offset in
// and there are "length" bytes available, else NULL is returned.
//----------------------------------------------------------------------
const uint8_t*
DataExtractor::PeekData (uint32_t offset, uint32_t length) const
{
    if ( length > 0 && ValidOffsetForDataOfSize(offset, length) )
        return m_start + offset;
    return NULL;
}

//----------------------------------------------------------------------
// Returns a pointer to a bytes in this object's data at the offset
// pointed to by "offset_ptr". If "length" is zero or too large,
// then the offset pointed to by "offset_ptr" will not be updated
// and NULL will be returned.
//
// Returns a pointer to the data if the offset and length are valid,
// or NULL otherwise.
//----------------------------------------------------------------------
const void*
DataExtractor::GetData (uint32_t *offset_ptr, uint32_t length) const
{
    const uint8_t* bytes = NULL;
    register uint32_t offset = *offset_ptr;
    if ( length > 0 && ValidOffsetForDataOfSize(offset, length) )
    {
        bytes = m_start + offset;
        *offset_ptr = offset + length;
    }
    return bytes;
}

//----------------------------------------------------------------------
// Extracts a AsCString (fixed length, or variable length) from
// the data at the offset pointed to by "offset_ptr". If
// "length" is zero, then a variable length NULL terminated C
// string will be extracted from the data the "offset_ptr" will be
// updated with the offset of the byte that follows the NULL
// terminator byte. If "length" is greater than zero, then
// the function will make sure there are "length" bytes
// available in the current data and if so, return a valid pointer.
//
// If the offset pointed to by "offset_ptr" is out of bounds, or if
// "length" is non-zero and there aren't enough avaialable
// bytes, NULL will be returned and "offset_ptr" will not be
// updated.
//----------------------------------------------------------------------
const char*
DataExtractor::GetCStr (uint32_t *offset_ptr) const
{
    const char *s = NULL;
    if ( m_start < m_end )
    {
        s = (char*)m_start + *offset_ptr;

        size_t length = strlen(s) + 1;

        if (!ValidOffsetForDataOfSize(*offset_ptr, length))
            return NULL;

        // Advance the offset
        *offset_ptr += length;
    }
    return s;
}

//------------------------------------------------------------------
// Peeks at a string in the contained data. No verification is done
// to make sure the entire string lies within the bounds of this
// object's data, only "offset" is verified to be a valid offset.
//
// Returns a valid C string pointer if "offset" is a valid offset in
// this object's data, else NULL is returned.
//------------------------------------------------------------------
const char *
DataExtractor::PeekCStr (uint32_t offset) const
{
    if (ValidOffset (offset))
        return (const char*)m_start + offset;
    return NULL;
}

//----------------------------------------------------------------------
// Extracts an unsigned LEB128 number from this object's data
// starting at the offset pointed to by "offset_ptr". The offset
// pointed to by "offset_ptr" will be updated with the offset of the
// byte following the last extracted byte.
//
// Returned the extracted integer value.
//----------------------------------------------------------------------
uint64_t
DataExtractor::GetULEB128 (uint32_t *offset_ptr) const
{
    uint64_t result = 0;
    if ( m_start < m_end )
    {
        int shift = 0;
        const uint8_t *src = m_start + *offset_ptr;
        uint8_t byte;
        int bytecount = 0;

        while (src < m_end)
        {
            bytecount++;
            byte = *src++;
            result |= (byte & 0x7f) << shift;
            shift += 7;
            if ((byte & 0x80) == 0)
                break;
        }

        *offset_ptr += bytecount;
    }
    return result;
}

//----------------------------------------------------------------------
// Extracts an signed LEB128 number from this object's data
// starting at the offset pointed to by "offset_ptr". The offset
// pointed to by "offset_ptr" will be updated with the offset of the
// byte following the last extracted byte.
//
// Returned the extracted integer value.
//----------------------------------------------------------------------
int64_t
DataExtractor::GetSLEB128 (uint32_t *offset_ptr) const
{
    int64_t result = 0;

    if ( m_start < m_end )
    {
        int shift = 0;
        int size = sizeof (uint32_t) * 8;
        const uint8_t *src = m_start + *offset_ptr;

        uint8_t byte = 0;
        int bytecount = 0;

        while (src < m_end)
        {
            bytecount++;
            byte = *src++;
            result |= (byte & 0x7f) << shift;
            shift += 7;
            if ((byte & 0x80) == 0)
                break;
        }

        // Sign bit of byte is 2nd high order bit (0x40)
        if (shift < size && (byte & 0x40))
            result |= - (1 << shift);

        *offset_ptr += bytecount;
    }
    return result;
}

//----------------------------------------------------------------------
// Skips a ULEB128 number (signed or unsigned) from this object's
// data starting at the offset pointed to by "offset_ptr". The
// offset pointed to by "offset_ptr" will be updated with the offset
// of the byte following the last extracted byte.
//
// Returns the number of bytes consumed during the extraction.
//----------------------------------------------------------------------
uint32_t
DataExtractor::Skip_LEB128 (uint32_t *offset_ptr) const
{
    uint32_t bytes_consumed = 0;
    if ( m_start < m_end )
    {
        const uint8_t *start = m_start + *offset_ptr;
        const uint8_t *src = start;

        while ((src < m_end) && (*src++ & 0x80))
            ++bytes_consumed;

        *offset_ptr += src - start;
    }
    return bytes_consumed;
}

uint32_t
DataExtractor::Dump
(
    Stream *s,
    uint32_t start_offset,
    lldb::Format item_format,
    uint32_t item_byte_size,
    uint32_t item_count,
    uint32_t num_per_line,
    uint64_t base_addr,
    uint32_t item_bit_size,     // If zero, this is not a bitfield value, if non-zero, the value is a bitfield
    uint32_t item_bit_offset    // If "item_bit_size" is non-zero, this is the shift amount to apply to a bitfield
) const
{
    if (s == NULL)
        return start_offset;

    uint32_t offset;
    uint32_t count;
    uint32_t line_start_offset;

    if (item_format == eFormatPointer)
    {
        if (item_byte_size != 4 && item_byte_size != 8)
            item_byte_size = s->GetAddressByteSize();
    }

    for (offset = start_offset, line_start_offset = start_offset, count = 0; ValidOffset(offset) && count < item_count; ++count)
    {
        if ((count % num_per_line) == 0)
        {
            if (count > 0)
            {
                if (item_format == eFormatBytesWithASCII && offset > line_start_offset)
                {
                    s->Printf("%*s", (num_per_line - (offset - line_start_offset)) * 3 + 2, "");
                    Dump(s, line_start_offset, eFormatCharPrintable, 1, offset - line_start_offset, UINT32_MAX, LLDB_INVALID_ADDRESS, 0, 0);
                }
                s->EOL();
            }
            if (base_addr != LLDB_INVALID_ADDRESS)
                s->Printf ("0x%8.8llx: ", (uint64_t)(base_addr + (offset - start_offset)));
            line_start_offset = offset;
        }
        else
        if (item_format != eFormatChar &&
            item_format != eFormatCharPrintable &&
            count > 0)
        {
            s->PutChar(' ');
        }

        uint32_t i;
        switch (item_format)
        {
        case eFormatBoolean:
            s->Printf ("%s", GetMaxU64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset) ? "true" : "false");
            break;

        case eFormatBinary:
            {
                uint64_t uval64 = GetMaxU64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset);
                std::string binary_value(std::bitset<64>(uval64).to_string());
                if (item_bit_size > 0)
                    s->Printf("0b%s", binary_value.c_str() + 64 - item_bit_size);
                else if (item_byte_size > 0 && item_byte_size <= 8)
                    s->Printf("0b%s", binary_value.c_str() + 64 - item_byte_size * 8);
            }
            break;

        case eFormatBytes:
        case eFormatBytesWithASCII:
            for (i=0; i<item_byte_size; ++i)
            {
                s->Printf ("%2.2x", GetU8(&offset));
            }
            // Put an extra space between the groups of bytes if more than one
            // is being dumped in a group (item_byte_size is more than 1).
            if (item_byte_size > 1)
                s->PutChar(' ');
            break;

        case eFormatChar:
        case eFormatCharPrintable:
            {
                // If we are only printing one character surround it with single
                // quotes
                if (item_count == 1 && item_format == eFormatChar)
                    s->PutChar('\'');

                uint8_t ch = GetU8(&offset);
                if (isprint(ch))
                    s->Printf ("%c", ch);
                else if (item_format == eFormatChar)
                {
                    switch (ch)
                    {
                    case '\e': s->Printf ("\\e", (uint8_t)ch); break;
                    case '\a': s->Printf ("\\a", ch); break;
                    case '\b': s->Printf ("\\b", ch); break;
                    case '\f': s->Printf ("\\f", ch); break;
                    case '\n': s->Printf ("\\n", ch); break;
                    case '\r': s->Printf ("\\r", ch); break;
                    case '\t': s->Printf ("\\t", ch); break;
                    case '\v': s->Printf ("\\v", ch); break;
                    case '\0': s->Printf ("\\0", ch); break;
                    default:   s->Printf ("\\x%2.2x", ch); break;
                    }
                }
                else
                {
                    s->PutChar(NON_PRINTABLE_CHAR);
                }

                // If we are only printing one character surround it with single quotes
                if (item_count == 1 && item_format == eFormatChar)
                    s->PutChar('\'');
            }
            break;

        case eFormatComplex:
            if (sizeof(float) * 2 == item_byte_size)
            {
                uint32_t a32 = GetU32(&offset);
                uint32_t b32 = GetU32(&offset);

                s->Printf ("%g + %gi", a32, b32);
            }
            else if (sizeof(double) * 2 == item_byte_size)
            {
                uint64_t a64 = GetU64(&offset);
                uint64_t b64 = GetU64(&offset);

                s->Printf ("%lg + %lgi", a64, b64);
            }
            else if (sizeof(long double) * 2 == item_byte_size && sizeof(long double) <= sizeof(uint64_t))
            {
                uint64_t a64 = GetU64(&offset);
                uint64_t b64 = GetU64(&offset);
                s->Printf ("%Lg + %Lgi", a64, b64);
            }
            break;

        case eFormatDecimal:
            if (item_byte_size <= 8)
                s->Printf ("%lld", GetMaxS64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset));
            break;

        case eFormatUnsigned:
            if (item_byte_size <= 8)
                s->Printf ("%llu", GetMaxU64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset));
            break;

        case eFormatOctal:
            if (item_byte_size <= 8)
                s->Printf ("0%llo", GetMaxS64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset));
            break;

        case eFormatEnum:
            // Print enum value as a signed integer when we don't get the enum type
            s->Printf ("%lld", GetMaxU64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset));
            break;

        case eFormatCString:
            {
                const char *cstr = GetCStr(&offset);
                if (cstr)
                    s->Printf("\"%s\"", cstr);
                else
                {
                    s->Printf("NULL", cstr);
                    offset = UINT32_MAX;
                }
            }
            break;


        case eFormatPointer:
            s->Address(GetMaxU64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset), sizeof (addr_t));
            break;

        default:
        case eFormatDefault:
        case eFormatHex:
            if (item_byte_size <= 8)
            {
                s->Printf("0x%*.*llx", 2 * item_byte_size, 2 * item_byte_size, GetMaxU64Bitfield(&offset, item_byte_size, item_bit_size, item_bit_offset));
            }
            else
            {
                assert (item_bit_size == 0 && item_bit_offset == 0);
                s->PutCString("0x");
                int32_t start_idx, end_idx, delta;
                if (m_byte_order == eByteOrderBig)
                {
                    start_idx = offset;
                    end_idx = offset + item_byte_size;
                    delta = 1;
                }
                else
                {
                    start_idx = offset + item_byte_size - 1;
                    end_idx = -1;
                    delta = -1;
                }
                const uint8_t *bytes = (const uint8_t* )GetData(&offset, item_byte_size);
                if (bytes)
                {
                    for (int32_t idx = start_idx; idx != end_idx; idx += delta)
                        s->Printf("%2.2x", bytes[idx]);
                }
            }
            break;

        case eFormatFloat:
            if (sizeof(float) == item_byte_size)
            {
                uint32_t a32 = GetU32(&offset);
                s->Printf ("%g", (double)(*((float *)&a32)));
            }
            else if (sizeof(double) == item_byte_size)
            {
                uint64_t a64 = GetU64(&offset);
                s->Printf ("%lg", (*((double *)&a64)));
            }
            else if (sizeof(long double) == item_byte_size && sizeof(long double) <= sizeof(uint64_t))
            {
                uint64_t a64 = GetU64(&offset);
                s->Printf ("%Lg", (*((long double *)&a64)));
            }
            break;

        case eFormatUnicode16:
            s->Printf("0x%4.4x", GetU16 (&offset));
            break;

        case eFormatUnicode32:
            s->Printf("0x%8.8x", GetU32 (&offset));
            break;

        case eFormatVectorOfChar:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatChar, 1, item_byte_size, item_byte_size, LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfSInt8:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatDecimal, 1, item_byte_size, item_byte_size, LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfUInt8:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatHex, 1, item_byte_size, item_byte_size, LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfSInt16:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatDecimal, sizeof(uint16_t), item_byte_size / sizeof(uint16_t), item_byte_size / sizeof(uint16_t), LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfUInt16:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatHex,     sizeof(uint16_t), item_byte_size / sizeof(uint16_t), item_byte_size / sizeof(uint16_t), LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfSInt32:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatDecimal, sizeof(uint32_t), item_byte_size / sizeof(uint32_t), item_byte_size / sizeof(uint32_t), LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfUInt32:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatHex,     sizeof(uint32_t), item_byte_size / sizeof(uint32_t), item_byte_size / sizeof(uint32_t), LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfSInt64:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatDecimal, sizeof(uint64_t), item_byte_size / sizeof(uint64_t), item_byte_size / sizeof(uint64_t), LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfUInt64:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatHex,     sizeof(uint32_t), item_byte_size / sizeof(uint32_t), item_byte_size / sizeof(uint32_t), LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfFloat32:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatFloat,       4, item_byte_size / 4, item_byte_size / 4, LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfFloat64:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatFloat,       8, item_byte_size / 8, item_byte_size / 8, LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;

        case eFormatVectorOfUInt128:
            s->PutChar('{');
            offset = Dump (s, start_offset, eFormatHex, 16, item_byte_size / 16, item_byte_size / 16, LLDB_INVALID_ADDRESS, 0, 0);
            s->PutChar('}');
            break;
        }
    }

    if (item_format == eFormatBytesWithASCII && offset > line_start_offset)
    {
        s->Printf("%*s", (num_per_line - (offset - line_start_offset)) * 3 + 2, "");
        Dump(s, line_start_offset, eFormatCharPrintable, 1, offset - line_start_offset, UINT32_MAX, LLDB_INVALID_ADDRESS, 0, 0);
    }
    return offset;  // Return the offset at which we ended up
}

//----------------------------------------------------------------------
// Dumps bytes from this object's data to the stream "s" starting
// "start_offset" bytes into this data, and ending with the byte
// before "end_offset". "base_addr" will be added to the offset
// into the dumped data when showing the offset into the data in the
// output information. "num_per_line" objects of type "type" will
// be dumped with the option to override the format for each object
// with "type_format". "type_format" is a printf style formatting
// string. If "type_format" is NULL, then an appropriate format
// string will be used for the supplied "type". If the stream "s"
// is NULL, then the output will be send to Log().
//----------------------------------------------------------------------
uint32_t
DataExtractor::PutToLog
(
    Log *log,
    uint32_t start_offset,
    uint32_t length,
    uint64_t base_addr,
    uint32_t num_per_line,
    DataExtractor::Type type,
    const char *format
) const
{
    if (log == NULL)
        return start_offset;

    uint32_t offset;
    uint32_t end_offset;
    uint32_t count;
    StreamString sstr;
    for (offset = start_offset, end_offset = offset + length, count = 0; ValidOffset(offset) && offset < end_offset; ++count)
    {
        if ((count % num_per_line) == 0)
        {
            // Print out any previous string
            if (sstr.GetSize() > 0)
            {
                log->Printf("%s", sstr.GetData());
                sstr.Clear();
            }
            // Reset string offset and fill the current line string with address:
            if (base_addr != LLDB_INVALID_ADDRESS)
                sstr.Printf("0x%8.8llx:", (uint64_t)(base_addr + (offset - start_offset)));
        }

        switch (type)
        {
            default:
            case TypeUInt8:   sstr.Printf (format ? format : " %2.2x", GetU8(&offset)); break;
            case TypeChar:
                {
                    char ch = GetU8(&offset);
                    sstr.Printf (format ? format : " %c",    isprint(ch) ? ch : ' ');
                }
                break;
            case TypeUInt16:  sstr.Printf (format ? format : " %4.4x",       GetU16(&offset)); break;
            case TypeUInt32:  sstr.Printf (format ? format : " %8.8x",       GetU32(&offset)); break;
            case TypeUInt64:  sstr.Printf (format ? format : " %16.16llx",   GetU64(&offset)); break;
            case TypePointer: sstr.Printf (format ? format : " 0x%llx",      GetAddress(&offset)); break;
            case TypeULEB128: sstr.Printf (format ? format : " 0x%llx",      GetULEB128(&offset)); break;
            case TypeSLEB128: sstr.Printf (format ? format : " %lld",        GetSLEB128(&offset)); break;
        }
    }

    if (sstr.GetSize() > 0)
        log->Printf("%s", sstr.GetData());

    return offset;  // Return the offset at which we ended up
}

//----------------------------------------------------------------------
// DumpUUID
//
// Dump out a UUID starting at 'offset' bytes into the buffer
//----------------------------------------------------------------------
void
DataExtractor::DumpUUID (Stream *s, uint32_t offset) const
{
    if (s)
    {
        const uint8_t *uuid_data = PeekData(offset, 16);
        if ( uuid_data )
        {
            UUID uuid(uuid_data, 16);
            uuid.Dump(s);
        }
        else
        {
            s->Printf("<not enough data for UUID at offset 0x%8.8x>", offset);
        }
    }
}


