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

#include "symbolize/dwarf3ranges.h"

#include "base/logging.h"
#include "symbolize/bytereader.h"
#include "symbolize/bytereader-inl.h"

namespace devtools_crosstool_autofdo {

void AddressRangeList::ReadRangeList(uint64 offset, uint64 base,
    AddressRangeList::RangeList* ranges) {

    if (is_dwarf5_) {
        ReadDwarf5RangeList(offset, base, ranges);
    }
    else {
        ReadDwarf3RangeList(offset, base, ranges);
    }

}

void AddressRangeList::ReadDwarf3RangeList(uint64 offset, uint64 base,
                                     AddressRangeList::RangeList* ranges) {
  CHECK(!is_dwarf5_);
  uint8 width = reader_->AddressSize();

  uint64 largest_address;
  if (width == 4)
    largest_address = 0xffffffffL;
  else if (width == 8)
    largest_address = 0xffffffffffffffffLL;
  else
    LOG(FATAL) << "width==" << width << " must be 4 or 8";

  const char* pos = buffer_ + offset;
  do {
    CHECK((pos + 2*width) <= (buffer_ + buffer_length_));
    uint64 start = reader_->ReadAddress(pos);
    uint64 stop = reader_->ReadAddress(pos+width);
    if (start == largest_address)
      base = stop;
    else if (start == 0 && stop == 0)
      break;
    else
      ranges->push_back(make_pair(start+base, stop+base));
    pos += 2*width;
  } while (true);
}

void AddressRangeList::ReadDwarf5RangeList(uint64 offset, uint64 base,
    AddressRangeList::RangeList* ranges) {

    CHECK(is_dwarf5_);

    const char* pos = buffer_ + offset;
    bool read_next_entry = true;

    do {
        CHECK(pos + 1 < buffer_ + buffer_length_);
        uint8 entry_kind = reader_->ReadOneByte(pos);
        pos += 1;

        switch (entry_kind) {
        case DW_RLE_end_of_list:
          read_next_entry = false;
          break;
        case DW_RLE_base_addressx:
          CHECK(0);
          break;
        case  DW_RLE_startx_endx:
          CHECK(0);
          break;
        case DW_RLE_startx_length:
          CHECK(0);
          break;
        case DW_RLE_offset_pair: {
          size_t len = 0;
          uint64 start = reader_->ReadUnsignedLEB128(pos, &len);
          pos += len;
          CHECK(pos <= (buffer_ + buffer_length_));
          uint64 stop = reader_->ReadUnsignedLEB128(pos, &len);
          pos += len;
          CHECK(pos <= (buffer_ + buffer_length_));
          if (start != stop) {
            ranges->push_back(make_pair(start + base, stop + base));
          }
          break;
        }
        case DW_RLE_base_address:
          CHECK((pos + address_size_) <= (buffer_ + buffer_length_));
          base = reader_->ReadAddress(pos);
          pos += address_size_;
          break;
        case DW_RLE_start_end:
          CHECK(0);
          break;
        case DW_RLE_start_length:
          CHECK(0);
          break;
        default:
          LOG(FATAL) << "Unhandled range list entry kind";
          break;
        }
    } while (read_next_entry);
}

void AddressRangeList::ReadDwarf5RangeListHeader() {
    CHECK(is_dwarf5_);

    const char* headerptr = buffer_;
    size_t initial_length_size;

    CHECK(headerptr + 4 < buffer_ + buffer_length_);
    const uint64 initial_length = reader_->ReadInitialLength(headerptr, &initial_length_size);

    CHECK(buffer_ + initial_length_size + initial_length <= buffer_ + buffer_length_);
    headerptr += initial_length_size;

    CHECK(headerptr + 2 < buffer_ + buffer_length_);
    uint16 version = reader_->ReadTwoBytes(headerptr);
    CHECK(version == 5);
    headerptr += 2;

    CHECK(headerptr + 1 < buffer_ + buffer_length_);
    address_size_ = reader_->ReadOneByte(headerptr);
    headerptr += 1;

    CHECK(headerptr + 1 < buffer_ + buffer_length_);
    uint8 segment_selector_size = reader_->ReadOneByte(headerptr);
    headerptr += 1;

    CHECK(headerptr + 4 < buffer_ + buffer_length_);
    offset_entry_count_ = reader_->ReadFourBytes(headerptr);
    headerptr += 4;

    after_header_ = headerptr;
}

}  // namespace devtools_crosstool_autofdo
