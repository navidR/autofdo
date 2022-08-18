// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef AUTOFDO_SYMBOLIZE_DWARF3RANGES_H_
#define AUTOFDO_SYMBOLIZE_DWARF3RANGES_H_

#include <algorithm>
#include <utility>
#include <vector>

#include "base/common.h"
#include "symbolize/bytereader.h"

namespace devtools_crosstool_autofdo {

// Entry kinds for DWARF5 non-contiguous address ranges
enum DwarfRangeListEntryKind {
  DW_RLE_end_of_list = 0,
  DW_RLE_base_addressx = 1,
  DW_RLE_startx_endx = 2,
  DW_RLE_startx_length = 3,
  DW_RLE_offset_pair = 4,
  DW_RLE_base_address = 5,
  DW_RLE_start_end = 6,
  DW_RLE_start_length = 7
};

struct RngListsSectionHeader{
  uint64 unit_length;
  uint8 version; 
  uint8 address_size;
  uint8 segment_selector_size;
  uint32 offset_entry_count;
};

// This class represents a DWARF3 non-contiguous address range.  The
// contents of an address range section are passed in
// (e.g. .debug_ranges) and subsequently, an interpretation of any
// offset in the section can be requested.
class AddressRangeList {
 public:
  typedef pair<uint64, uint64> Range;
  typedef vector<Range> RangeList;
  AddressRangeList(const char* buffer,
                   uint64 buffer_length,
                   ByteReader* reader,
                   bool is_rnglists_section,
                   const char* addr_buffer,
                   uint64 addr_buffer_length)
      : reader_(reader),
        buffer_(buffer),
        buffer_length_(buffer_length),
        is_rnglists_section(is_rnglists_section),
        after_header_(buffer),
        rnglist_base_(0),
        addr_buffer_(addr_buffer),
        addr_buffer_length_(addr_buffer_length),
        offset_list_() {
      if (is_rnglists_section) {
          ReadDwarfRngListsHeader();
      }
  }

  void ReadRangeList(uint64 offset, uint64 base,
                     RangeList* output, uint64 addr_base = 0);

  // This does handle case where we read ranges with DW_FORM_sec_offset
  // In this case, the buffer does not have offset array (or the offset passed to us)
  // does include the offset array too. So for calculating the position, 
  // we only add the offset to buffer_.
  void ReadDwarfRngListsDirectly(uint64 offset, uint64 base,
                                 AddressRangeList::RangeList* ranges, uint64 addr_base);

  // In this case DW_FORM_rnglistx, buffer_ does include offset array too.
  // So we have to add that to the the buffer_ to be able to read the RngLists.
  void ReadDwarfRngListwithOffsetArray(uint64 offset, uint64 base,
                                       AddressRangeList::RangeList* ranges, uint64 addr_base);

  static uint64 RangesMin(const RangeList *ranges) {
    if (ranges->size() == 0)
      return 0;

    uint64 result = kint64max;
    for (AddressRangeList::RangeList::const_iterator iter =
             ranges->begin();
         iter != ranges->end(); ++iter) {
      result = min(result, iter->first);
    }
    return result;
  }

  bool IsRngListsSection() {
    return is_rnglists_section;
  }

  const char* GetRngListsElementAddressByIndex(uint64 rng_index);

 private:

  uint64 ReadOffset(const char** offsetarrayptr);

  void ReadDwarfRngListsHeader();

  void ReadDwarfRngListsOffsetArray(const char* headerptr);

  void ReadDwarfRangeList(uint64 offset, uint64 base,
                           RangeList* output);

  void ReadDwarfRngLists(uint64 base, RangeList* output, const char* pos, uint64 addr_base);



  // The associated ByteReader that handles endianness issues for us
  ByteReader* reader_;

  // buffer is the buffer for our range info
  const char* buffer_;
  uint64 buffer_length_;
  const char* addr_buffer_;
  uint64 addr_buffer_length_;
  bool is_rnglists_section;
  const char* after_header_;
  const char* rnglist_base_;
  std::vector<uint32> offset_list_;

  RngListsSectionHeader header_;

  DISALLOW_COPY_AND_ASSIGN(AddressRangeList);
};

}  // namespace devtools_crosstool_autofdo

#endif  // AUTOFDO_SYMBOLIZE_DWARF3RANGES_H_
