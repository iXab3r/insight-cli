// MIT first-party facade over the unmodified Apache-2.0 LIEF library.
#include <LIEF/LIEF.hpp>
#include "json.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <limits>
using Json=nlohmann::json;
static std::string hex(uint64_t value){std::ostringstream out;out<<"0x"<<std::hex<<value;return out.str();}
static std::string label(const std::string& name){if(name.size()>4096)throw std::runtime_error("Binary metadata string exceeds 4096 bytes");return name;}
static std::string format(const LIEF::Binary& binary){switch(binary.format()){case LIEF::Binary::PE:return "PE";case LIEF::Binary::ELF:return "ELF";case LIEF::Binary::MACHO:return "MachO";default:throw std::runtime_error("Only PE, ELF and thin Mach-O are admitted");}}
static uint64_t absolute(uint64_t base,uint64_t rva){if(rva>std::numeric_limits<uint64_t>::max()-base)throw std::runtime_error("PE address overflow");return base+rva;}
static Json query(const Json& plan,LIEF::Binary& binary){
 const auto view=plan.value("view",std::string("overview"));const auto filter=plan.value("filter",std::string(""));const size_t limit=plan.value("limit",50),offset=plan.value("offset",0);Json rows=Json::array();size_t scanned=0,matching=0;bool complete=true;
 auto add=[&](const std::string& name,Json row){if(++scanned>100000){complete=false;return false;}if(!filter.empty()&&name.find(filter)==std::string::npos)return true;if(matching++>=offset&&rows.size()<limit)rows.push_back(std::move(row));return true;};
 Json result={{"state","completed"},{"complete",true},{"format",format(binary)},{"view",view},{"scope","Static parsed LIEF metadata; no target execution. Warnings or omitted/malformed tables do not prove absence. Addresses belong to this exact input and declared format; Mach-O universal containers require explicit slice extraction."}};
 if(view=="overview"){
  auto header=binary.header();Json data={{"architecture",LIEF::to_string(header.architecture())},{"objectType",LIEF::to_string(header.object_type())},{"entryPoint",hex(binary.entrypoint())},{"imageBase",hex(binary.imagebase())},{"sections",binary.sections().size()},{"libraries",binary.imported_libraries().size()},{"importedFunctions",binary.imported_functions().size()},{"exportedFunctions",binary.exported_functions().size()}};
  if(auto* pe=dynamic_cast<LIEF::PE::Binary*>(&binary)){data["subsystem"]=static_cast<unsigned>(pe->optional_header().subsystem());data["hasAuthenticode"]=pe->has_signatures();}
  result["data"]=data;return result;
 }
 if(view=="sections"){for(const auto& section:binary.sections())if(!add(section.name(),{{"name",label(section.name())},{"fileOffset",hex(section.offset())},{"fileSize",std::to_string(section.size())},{"virtualAddress",hex(section.virtual_address())}}))break;}
 else if(view=="libraries"){for(const auto& library:binary.imported_libraries())if(!add(library,{{"name",label(library)}}))break;}
 else if(view=="exports"){
  if(auto* pe=dynamic_cast<LIEF::PE::Binary*>(&binary)){if(const auto* table=pe->get_export())for(const auto& symbol:table->entries()){Json row={{"name",label(symbol.name())},{"ordinal",symbol.ordinal()},{"rva",hex(symbol.address())},{"forwarded",symbol.is_forwarded()}};if(symbol.is_forwarded()){const auto forward=symbol.forward_information();row["forward"]={{"library",label(forward.library)},{"function",label(forward.function)}};}else row["virtualAddress"]=hex(absolute(binary.imagebase(),symbol.address()));if(!add(symbol.name(),row))break;}}
  else for(const auto& symbol:binary.exported_functions())if(!add(symbol.name(),{{"name",label(symbol.name())},{"virtualAddress",hex(symbol.address())},{"forwarded",false}}))break;
 }
 else if(view=="imports"){
  if(auto* pe=dynamic_cast<LIEF::PE::Binary*>(&binary)){bool stop=false;for(const auto& library:pe->imports()){for(const auto& entry:library.entries()){Json row={{"library",label(library.name())},{"byOrdinal",entry.is_ordinal()}};if(entry.is_ordinal())row["ordinal"]=entry.ordinal();else row["name"]=label(entry.name());if(!add(library.name()+"!"+entry.name(),row)){stop=true;break;}}if(stop)break;}}
  else for(const auto& symbol:binary.imported_functions())if(!add(symbol.name(),{{"name",label(symbol.name())},{"virtualAddress",hex(symbol.address())},{"libraryKnown",false}}))break;
 }
 else throw std::runtime_error("Unknown structured binary view");
 result["state"]=complete?"completed":"partial";result["complete"]=complete;if(!complete)result["reason"]="metadata_scan_bound";result["items"]=rows;result["matchingInScannedPrefix"]=matching;result["scannedRecords"]=std::min(scanned,size_t(100000));result["limit"]=limit;result["offset"]=offset;result["truncated"]=offset+limit<matching;return result;
}
static Json edit(const Json& plan,LIEF::Binary& binary){
 auto* pe=dynamic_cast<LIEF::PE::Binary*>(&binary);if(!pe)throw std::runtime_error("Subsystem edit requires a PE input");const auto expected=plan.at("expectedSubsystem").get<unsigned>(),value=plan.at("subsystem").get<unsigned>();if((expected!=2&&expected!=3)||(value!=2&&value!=3)||expected==value)throw std::runtime_error("Select an actual guarded console/GUI subsystem change");if(static_cast<unsigned>(pe->optional_header().subsystem())!=expected)throw std::runtime_error("PE subsystem differs from the explicit expectation");
 const uint64_t offset=uint64_t(pe->dos_header().addressof_new_exeheader())+4+20+68;const auto input=plan.at("input").get<std::string>(),output=plan.at("output").get<std::string>();std::ifstream in(input,std::ios::binary);std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),{});if(pe->header().sizeof_optional_header()<70||offset+2>bytes.size()||unsigned(bytes[offset]|(bytes[offset+1]<<8))!=expected)throw std::runtime_error("PE optional-header field binding failed");
 if(std::filesystem::exists(output))throw std::runtime_error("Internal edit output already exists");bytes[offset]=static_cast<uint8_t>(value);bytes[offset+1]=0;std::ofstream out(output,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());out.close();if(!out)throw std::runtime_error("New PE copy could not be completed");auto readback=LIEF::PE::Parser::parse(output);if(!readback||static_cast<unsigned>(readback->optional_header().subsystem())!=value)throw std::runtime_error("Independent LIEF readback rejected the new subsystem");
 return {{"state","completed"},{"complete",true},{"format","PE"},{"changedField","optionalHeader.subsystem"},{"before",expected},{"after",value},{"fieldOffset",hex(offset)},{"byteRangeLength",2},{"scope","New copy, original preserved; exactly the existing two-byte subsystem field is assigned. Existing PE checksum/Authenticode signatures are not recomputed and may be invalidated. Header readback is not execution compatibility proof."}};
}
int main(int argc,char** argv){try{
 if(argc!=2||!std::filesystem::path(argv[1]).is_absolute()||std::filesystem::file_size(argv[1])>16384)throw std::runtime_error("A bounded absolute private plan is required");std::ifstream file(argv[1]);const Json plan=Json::parse(file);const auto input=plan.at("input").get<std::string>();if(plan.at("schema")!=1||!std::filesystem::path(input).is_absolute()||std::filesystem::file_size(input)>64*1024*1024)throw std::runtime_error("Unsupported input size or identity");if(LIEF::MachO::is_fat(input))throw std::runtime_error("Select an explicit thin Mach-O slice; universal selection is not implicit");const auto limit=plan.value("limit",50),offset=plan.value("offset",0);if(limit<1||limit>500||offset<0||offset>1000000)throw std::runtime_error("Invalid query page bounds");auto binary=LIEF::Parser::parse(input);if(!binary)throw std::runtime_error("Input is not a parsed supported executable");const auto mode=plan.at("mode").get<std::string>();Json result;if(mode=="query")result=query(plan,*binary);else if(mode=="edit-subsystem")result=edit(plan,*binary);else throw std::runtime_error("Unknown binary operation");std::cout<<result.dump()<<'\n';return 0;
 }catch(const std::exception& error){std::cout<<Json({{"state","failed"},{"error",std::string(error.what()).substr(0,4096)}}).dump()<<'\n';return 70;}}
