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
    AddressRangeList::RangeList* ranges,  uint64 addr_base) {

    if (is_rnglists_section) {
        ReadDwarfRngListsDirectly(offset, base, ranges, addr_base);
    }
    else {
        ReadDwarfRangeList(offset, base, ranges);
    }

}

void AddressRangeList::ReadDwarfRangeList(uint64 offset, uint64 base,
                                     AddressRangeList::RangeList* ranges) {
  CHECK(!is_rnglists_section);
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


void AddressRangeList::ReadDwarfRngListsDirectly(uint64 offset, uint64 base,
                                            AddressRangeList::RangeList* ranges, uint64 addr_base) {
  ReadDwarfRngLists(base, ranges, buffer_ + offset, addr_base);
}

void AddressRangeList::ReadDwarfRngListwithOffsetArray(uint64 offset, uint64 base,
                                            AddressRangeList::RangeList* ranges, uint64 addr_base) {
  ReadDwarfRngLists(base, ranges, buffer_ + ((uint64) rnglist_base_) + offset, addr_base);
}

void AddressRangeList::ReadDwarfRngLists(uint64 base,
                                         AddressRangeList::RangeList* ranges,
                                         const char* pos, uint64 addr_base) {

    CHECK(is_rnglists_section);

    bool read_next_entry = true;

    // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
    // printf("Ranges:\n");
    int i = 0;

    do {
        ++i;
        CHECK(pos < buffer_ + buffer_length_);
        uint8 entry_kind = reader_->ReadOneByte(pos);
        pos += 1;

        switch (entry_kind) {
          case DW_RLE_end_of_list: {
            read_next_entry = false;
            break;
          }
          case DW_RLE_base_addressx: {
            CHECK(addr_buffer_ && addr_buffer_length_);
            size_t len = 0;
            uint64 addr_section_address = reader_->ReadUnsignedLEB128(pos, &len);
            CHECK((addr_buffer_ + addr_section_address) <= (addr_buffer_ + addr_buffer_length_));
            base = reader_->ReadAddress(addr_buffer_ + addr_section_address);
            break;
          }
          case DW_RLE_startx_endx: {
            CHECK(addr_buffer_ && addr_buffer_length_);
            size_t len = 0;
            // Start
            uint64 start_index = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));
            const char* start_ptr = addr_buffer_ + addr_base + start_index * reader_->AddressSize();
            CHECK(start_ptr <= (addr_buffer_ + addr_buffer_length_));
            uint64 start_addr = reader_->ReadAddress(start_ptr);
            // Stop
            uint64 stop_index = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));
            const char* stop_ptr = addr_buffer_ + addr_base + stop_index * reader_->AddressSize();
            CHECK(stop_ptr <= (addr_buffer_ + addr_buffer_length_));
            uint64 stop_addr = reader_->ReadAddress(stop_ptr);

            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            // printf("[0x%"PRIXPTR", 0x%"PRIXPTR")\n", start + base, stop + base);
            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            if ((start_addr + base) != (stop_addr + base))
              ranges->push_back (make_pair (start_addr + base, stop_addr + base));
            break;
          }
          case DW_RLE_startx_length: {
            CHECK(addr_buffer_ && addr_buffer_length_);
            size_t len = 0;
            // Start
            uint64 start_index = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));
            const char* start_ptr = addr_buffer_ + addr_base + start_index * reader_->AddressSize();
            CHECK(start_ptr <= (addr_buffer_ + addr_buffer_length_));
            uint64 start_addr = reader_->ReadAddress(start_ptr);
            // Length
            uint64 range_length = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));

            if ((start_addr + base) != (start_addr + base + range_length))
              ranges->push_back (make_pair (start_addr + base, start_addr + base + range_length));
            break;
          }
          case DW_RLE_offset_pair: {
            size_t len = 0;
            uint64 start = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));
            uint64 stop = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));

            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            // printf("[0x%"PRIXPTR", 0x%"PRIXPTR")\n", start + base, stop + base);
            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            if ((start + base) != (stop + base))
              ranges->push_back (make_pair (start + base, stop + base));
            break;
          }
          case DW_RLE_base_address: {
            CHECK((pos + header_.address_size) <= (buffer_ + buffer_length_));
            base = reader_->ReadAddress(pos);
            pos += header_.address_size;
            break;
          case DW_RLE_start_end:
            size_t len = 0;
            uint64 start = reader_->ReadAddress(pos);
            pos += header_.address_size;
            CHECK(pos <= (buffer_ + buffer_length_));
            uint64 stop = reader_->ReadAddress(pos);
            pos += header_.address_size;
            CHECK(pos <= (buffer_ + buffer_length_));

            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            // printf("[0x%"PRIXPTR", 0x%"PRIXPTR")\n", start + base, stop + base);
            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            if (start != stop)
              ranges->push_back (make_pair (start, stop));
            break;
          }
          case DW_RLE_start_length: {
            size_t len = 0;
            uint64 start = reader_->ReadAddress(pos);
            pos += header_.address_size;
            CHECK(pos <= (buffer_ + buffer_length_));
            // Length
            uint64 range_length = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));          

            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            // printf("[0x%"PRIXPTR", 0x%"PRIXPTR")\n", start + base, stop + base);
            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            if ((base + start) != (base + start + range_length))
              ranges->push_back (make_pair (base + start, base + start + range_length));
            break;
          }
          default: { 
            LOG(FATAL) << "Unhandled range list entry kind";
            break;
          }
        }
    } while (read_next_entry);
}

void AddressRangeList::ReadDwarfRngListsHeader() {
    CHECK(is_rnglists_section);

    const char* headerptr = buffer_;
    size_t initial_length_size;

    CHECK(headerptr + 4 < buffer_ + buffer_length_);
    // unit_length (initial length)
    header_.unit_length = reader_->ReadInitialLength(headerptr, &initial_length_size);

    CHECK(buffer_ + initial_length_size + header_.unit_length <= buffer_ + buffer_length_);
    headerptr += initial_length_size;
    rnglist_base_ += initial_length_size;

    CHECK(headerptr + 2 < buffer_ + buffer_length_);
    header_.version = reader_->ReadTwoBytes(headerptr);
    CHECK(header_.version == 5);
    headerptr += 2;
    rnglist_base_ += 2;

    CHECK(headerptr + 1 < buffer_ + buffer_length_);
    header_.address_size = reader_->ReadOneByte(headerptr);
    headerptr += 1;
    rnglist_base_ += 1;

    CHECK(headerptr + 1 < buffer_ + buffer_length_);
    header_.segment_selector_size = reader_->ReadOneByte(headerptr);
    headerptr += 1;
    rnglist_base_ += 1;

    CHECK(headerptr + 4 < buffer_ + buffer_length_);
    header_.offset_entry_count = reader_->ReadFourBytes(headerptr);
    headerptr += 4;
    rnglist_base_ += 4;

    if(header_.offset_entry_count != 0) {
      ReadDwarfRngListsOffsetArray(headerptr);
    }
}

const char* AddressRangeList::GetRngListsElementAddressByIndex(uint64 rng_index)  {
    if (header_.offset_entry_count == 0) {
      LOG(FATAL) << "If the offset_entry_count is zero, then DW_FORM_rnglistx cannot be used to access a range list; DW_FORM_sec_offset must be used instead. If the offset_entry_count is non-zero, then DW_FORM_rnglistx may be used to access a range list; this is necessary in split units and may be more compact than using DW_FORM_sec_offsetin non-split units. (Page 242, DWARF5 Specification document).";
    }
    CHECK(rng_index < offset_list_.size());
    // const char* addr_ptr = 
    //       buffer_ + rnglist_base_ + ((const char*) rng_index * reader_->OffsetSize());
    // // CHECK Correctness.
    // const char* address_ = (const char*) reader_->ReadOffset(addr_ptr);
    // return address_;  
    return (const char*) offset_list_[rng_index];
  }

uint64 AddressRangeList::ReadOffset(const char** offsetarrayptr)
{
    CHECK(*offsetarrayptr + reader_->OffsetSize() < buffer_ + buffer_length_);
    uint64 offset = reader_->ReadOffset(*offsetarrayptr);
    *offsetarrayptr = *offsetarrayptr + reader_->OffsetSize();
    // DEBUGDEBUG
    // printf("offset : 0x%"PRIXPTR"\n", offset);
    return offset;
}

void AddressRangeList::ReadDwarfRngListsOffsetArray(const char* headerptr) {
    for(int i = 0; i < header_.offset_entry_count; ++i) {
      offset_list_.push_back(ReadOffset(&headerptr));
    }
}

}  // namespace devtools_crosstool_autofdo
