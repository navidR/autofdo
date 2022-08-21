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
  // When we are reading with DW_FORM_sec_offset, the .debug_rnglists
  // does not care about which RngListsData we are using,
  // Since for the computation, we only need address_size.
  // and address size are same between all the rnglists in .debug_rnglists.
  auto i = rngdatamap_.begin();
  CHECK(i != rngdatamap_.end());
  RngListsData& rnglistsdata = i->second;                                               
  ReadDwarfRngLists(base, ranges, buffer_ + offset, addr_base, rnglistsdata);
}

void AddressRangeList::ReadDwarfRngListwithOffsetArray(uint64 offset, uint64 base,
                                            AddressRangeList::RangeList* ranges, uint64 addr_base, uint64 range_base_) {
  auto i = rngdatamap_.find(range_base_);
  CHECK(i != rngdatamap_.end());
  RngListsData& rnglistsdata = i->second;                                              
  ReadDwarfRngLists(base, ranges, buffer_ + rnglistsdata.rnglist_base_ + offset, addr_base, rnglistsdata);
}

void AddressRangeList::ReadDwarfRngLists(uint64 base,
                                         AddressRangeList::RangeList* ranges,
                                         const char* pos, uint64 addr_base,
                                         RngListsData& rnglistsdata) {

    CHECK(is_rnglists_section);

    bool read_next_entry = true;

    // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
    printf("Ranges:\n");
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
            printf("[0x%X, 0x%X)\n", start_addr + base, stop_addr + base);
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
            printf("[0x%X, 0x%X)\n", start + base, stop + base);
            if ((start + base) != (stop + base))
              ranges->push_back (make_pair (start + base, stop + base));
            break;
          }
          case DW_RLE_base_address: {
            CHECK((pos + rnglistsdata.address_size) <= (buffer_ + buffer_length_));
            base = reader_->ReadAddress(pos);
            pos += rnglistsdata.address_size;
            break;
          case DW_RLE_start_end:
            size_t len = 0;
            uint64 start = reader_->ReadAddress(pos);
            pos += rnglistsdata.address_size;
            CHECK(pos <= (buffer_ + buffer_length_));
            uint64 stop = reader_->ReadAddress(pos);
            pos += rnglistsdata.address_size;
            CHECK(pos <= (buffer_ + buffer_length_));

            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            printf("[0x%X, 0x%X)\n", start + base, stop + base);
            if (start != stop)
              ranges->push_back (make_pair (start, stop));
            break;
          }
          case DW_RLE_start_length: {
            size_t len = 0;
            uint64 start = reader_->ReadAddress(pos);
            pos += rnglistsdata.address_size;
            CHECK(pos <= (buffer_ + buffer_length_));
            // Length
            uint64 range_length = reader_->ReadUnsignedLEB128(pos, &len);
            pos += len;
            CHECK(pos <= (buffer_ + buffer_length_));          

            // DEBUGDEBUG: REMOVE BEFORE FINAL COMMIT
            printf("[0x%X, 0x%X)\n", base + start, base + start + range_length);
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

    const char* ptr = buffer_;

    do {
      const char* section_start_ptr = ptr;

      RngListsData rnglistsdata;

      CHECK(ptr + 12 < buffer_ + buffer_length_);
      // unit_length (initial length)
      size_t unit_length_size;
      rnglistsdata.unit_length = reader_->ReadInitialLength(ptr, &unit_length_size);

      CHECK(buffer_ + unit_length_size + rnglistsdata.unit_length <= buffer_ + buffer_length_);
      ptr += unit_length_size;

      CHECK(ptr + 2 < buffer_ + buffer_length_);
      rnglistsdata.version = reader_->ReadTwoBytes(ptr);
      CHECK(rnglistsdata.version == 5);
      ptr += 2;

      CHECK(ptr + 1 < buffer_ + buffer_length_);
      rnglistsdata.address_size = reader_->ReadOneByte(ptr);
      ptr += 1;

      CHECK(ptr + 1 < buffer_ + buffer_length_);
      rnglistsdata.segment_selector_size = reader_->ReadOneByte(ptr);
      ptr += 1;

      CHECK(ptr + 4 < buffer_ + buffer_length_);
      rnglistsdata.offset_entry_count = reader_->ReadFourBytes(ptr);
      ptr += 4;
      
      rnglistsdata.rnglist_base_ = ptr - buffer_;

      if(rnglistsdata.offset_entry_count != 0) {
        for(int i = 0; i < rnglistsdata.offset_entry_count; ++i) {
          rnglistsdata.offset_list_.push_back(ReadOffset(&ptr));
        }
      }
      rngdatamap_[rnglistsdata.rnglist_base_] = rnglistsdata;

      // Jump to next header inside .debug_rnglists
      ptr = section_start_ptr + (rnglistsdata.unit_length + unit_length_size); 
      
    } while(ptr < buffer_ + buffer_length_); 

}

const char* AddressRangeList::GetRngListsElementAddressByIndex(uint64 addr_base, uint64 rng_index) {
    auto i = rngdatamap_.find(addr_base);
    CHECK(i != rngdatamap_.end());
    RngListsData rnglistsdata = i->second;
    if (rnglistsdata.offset_entry_count == 0) {
      LOG(FATAL) << "If the offset_entry_count is zero, then DW_FORM_rnglistx cannot be used to access a range list; DW_FORM_sec_offset must be used instead. If the offset_entry_count is non-zero, then DW_FORM_rnglistx may be used to access a range list; this is necessary in split units and may be more compact than using DW_FORM_sec_offsetin non-split units. (Page 242, DWARF5 Specification document).";
    }
    CHECK(rng_index < rnglistsdata.offset_list_.size());
    // const char* addr_ptr = 
    //       buffer_ + rnglist_base_ + ((const char*) rng_index * reader_->OffsetSize());
    // // CHECK Correctness.
    // const char* address_ = (const char*) reader_->ReadOffset(addr_ptr);
    // return address_;  
    return (const char*) rnglistsdata.offset_list_[rng_index];
  }

uint64 AddressRangeList::ReadOffset(const char** offsetarrayptr)
{
    CHECK(*offsetarrayptr + reader_->OffsetSize() < buffer_ + buffer_length_);
    uint64 offset = reader_->ReadOffset(*offsetarrayptr);
    *offsetarrayptr = *offsetarrayptr + reader_->OffsetSize();
    // DEBUGDEBUG
    // printf("offset : 0x%X\n", offset);
    return offset;
}

}  // namespace devtools_crosstool_autofdo
