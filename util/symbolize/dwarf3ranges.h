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
                   bool is_dwarf5)
      : reader_(reader),
        buffer_(buffer),
        buffer_length_(buffer_length),
        is_dwarf5_(is_dwarf5),
        offset_entry_count_(0),
        after_header_(buffer) {
      if (is_dwarf5) {
          ReadDwarf5RangeListHeader();
      }
  }

  void ReadRangeList(uint64 offset, uint64 base,
                     RangeList* output);

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

 private:

  void ReadDwarf5RangeListHeader();

  void ReadDwarf3RangeList(uint64 offset, uint64 base,
                           RangeList* output);

  void ReadDwarf5RangeList(uint64 offset, uint64 base,
                           RangeList* output);

  // The associated ByteReader that handles endianness issues for us
  ByteReader* reader_;

  // buffer is the buffer for our range info
  const char* buffer_;
  uint64 buffer_length_;
  bool is_dwarf5_;
  uint64 offset_entry_count_;
  uint8 address_size_;
  const char* after_header_;

  DISALLOW_COPY_AND_ASSIGN(AddressRangeList);
};

}  // namespace devtools_crosstool_autofdo

#endif  // AUTOFDO_SYMBOLIZE_DWARF3RANGES_H_
