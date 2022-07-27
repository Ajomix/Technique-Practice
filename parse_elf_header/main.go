package main

import (
	"fmt"
	"os"
	"reflect"
	"unsafe"
)

type ELF32 struct {
	Ehdr Elf32_Ehdr
	Phdr []Elf32_Phdr
	Shdr []Elf32_Shdr
}
type Elf64_Ehdr struct {
}
type Elf32_Ehdr struct {
	e_ident     [16]uint8
	e_type      uint16
	e_machine   uint16
	e_version   uint32
	e_entry     uint32
	e_phoff     uint32
	e_shoff     uint32
	e_flags     uint32
	e_ehsize    uint16
	e_phentsize uint16
	e_phnum     uint16
	e_shentsize uint16
	e_shnum     uint16
	e_shstrndx  uint16
}
type Elf32_Phdr struct {
	p_type, p_offset,
	p_vaddr, p_paddr,
	p_filesz, p_memsz,
	p_flags, p_align uint32
}
type Elf32_Shdr struct {
	sh_name, sh_type,
	sh_flags, sh_addr,
	sh_offset, sh_size,
	sh_link, sh_info,
	sh_addralign, sh_entsize uint32
}

type Elf_parser interface {
	parse_Elf_header(b []byte)
	parse_Program_header(b []byte)
	parse_Section_header(b []byte)
}

func (elf_header *Elf32_Ehdr) parse_Elf_header(b *byte) {
	*elf_header = **(**Elf32_Ehdr)(unsafe.Pointer(&b))

}
func (program_header *Elf32_Phdr) parse_Program_header(b *byte) {
	*program_header = **(**Elf32_Phdr)(unsafe.Pointer(&b))
}
func (section_header *Elf32_Shdr) parse_Section_header(b *byte) {
	*section_header = **(**Elf32_Shdr)(unsafe.Pointer(&b))
}

func check_error(e error) {
	if e != nil {
		panic(e)
	}
}
func check_elf_magic(b []byte) bool {
	if b[0] != '\x7f' && b[1] != 'E' && b[2] != 'L' && b[3] != 'F' {
		return false
	}
	return true
}

const (
	SIZE_PHDR32 = int(unsafe.Sizeof(Elf32_Phdr{}))
	SIZE_EHDR32 = int(unsafe.Sizeof(Elf32_Ehdr{}))
	SIZE_SHDR32 = int(unsafe.Sizeof(Elf32_Shdr{}))
)

var (
	nested = map[string]map[int]string{
		"ei_class": {
			0: "NONE",
			1: "32 bit",
			2: "64 bit",
		},
		"ei_data": {
			0: "NONE",
			1: "2LSB",
			2: "2MSB",
		},
		"e_type": {
			0:      "ET_NONE",
			1:      "ET_REL",
			2:      "ET_EXEC",
			3:      "ET_DYN",
			4:      "ET_CORE",
			0xfe00: "ET_LOOS",
			0xfeff: "ET_HIOS",
			0xff00: "ET_LOPROC",
			0xffff: "ET_HIPROC",
		},
		"ei_osabi": {
			0:  "SYSV",
			1:  "HPUX",
			2:  "NETBSD",
			3:  "LINUX",
			4:  "HURD",
			5:  "86OPEN",
			6:  "SOLARIS",
			7:  "AIX",
			8:  "IRIX",
			9:  "FREEBSD",
			10: "TRU64",
			11: "MODESTO",
			12: "OPENBSD",
			13: "OPENNVMS",
			14: "NSK",
			15: "AROS",
			16: "FENIXIOS",
			17: "CLOUDABI",
			18: "ARM_AEABI",
			19: "ARM",
			20: "STANDALONE",
			//STILL MORE ..
		},
		"e_machine": {
			0:       "EM_NONE",
			1:       "EM_M32",
			2:       "EM_SPARC",
			3:       "EM_386",
			4:       "EM_68K",
			5:       "EM_88K",
			6:       "EM_IAMCU",
			7:       "EM_860",
			8:       "EM_MIPS",
			9:       "EM_S370",
			10:      "EM_MIPS_RS3_LE",
			11:      "reserved",
			12:      "reserved",
			13:      "reserved",
			14:      "reserved",
			15:      "EM_PARISC",
			16:      "reserved",
			17:      "EM_VPP500",
			18:      "EM_SPARC32PLUS",
			19:      "EM_960",
			20:      "EM_PPC",
			21:      "EM_PPC64",
			22:      "EM_S390",
			23:      "EM_SPU",
			24 - 35: "reserved",
			25:      "reserved",
			26:      "reserved",
			27:      "reserved",
			28:      "reserved",
			29:      "reserved",
			30:      "reserved",
			31:      "reserved",
			32:      "reserved",
			33:      "reserved",
			34:      "reserved",
			35:      "reserved",
			36:      "EM_V800",
			37:      "EM_FR20",
			38:      "EM_RH32",
			39:      "EM_RCE",
			40:      "EM_ARM",
			41:      "EM_ALPHA",
			42:      "EM_SH",
			43:      "EM_SPARCV9",
			44:      "EM_TRICORE",
			45:      "EM_ARC",
			46:      "EM_H8_300",
			47:      "EM_H8_300H",
			48:      "EM_H8S",
			49:      "EM_H8_500",
			50:      "EM_IA_64",
			51:      "EM_MIPS_X",
			52:      "EM_COLDFIRE",
			53:      "EM_68HC12",
			54:      "EM_MMA",
			55:      "EM_PCP",
			56:      "EM_NCPU",
			57:      "EM_NDR1",
			58:      "EM_STARCORE",
			59:      "EM_ME16",
			60:      "EM_ST100",
			61:      "EM_TINYJ",
			62:      "EM_X86_64",
			63:      "EM_PDSP",
			64:      "EM_PDP10",
			65:      "EM_PDP11",
			66:      "EM_FX66",
			67:      "EM_ST9PLUS",
			68:      "EM_ST7",
			69:      "EM_68HC16",
			70:      "EM_68HC11",
			71:      "EM_68HC08",
			72:      "EM_68HC05",
			73:      "EM_SVX",
			74:      "EM_ST19",
			75:      "EM_VAX",
			76:      "EM_CRIS",
			77:      "EM_JAVELIN",
			78:      "EM_FIREPATH",
			79:      "EM_ZSP",
			80:      "EM_MMIX",
			81:      "EM_HUANY",
			82:      "EM_PRISM",
			83:      "EM_AVR",
			84:      "EM_FR30",
			85:      "EM_D10V",
			86:      "EM_D30V",
			87:      "EM_V850",
			88:      "EM_M32R",
			89:      "EM_MN10300",
			90:      "EM_MN10200",
			91:      "EM_PJ",
			92:      "EM_OPENRISC",
			93:      "EM_ARC_COMPACT",
			94:      "EM_XTENSA",
			95:      "EM_VIDEOCORE",
			96:      "EM_TMM_GPP",
			97:      "EM_NS32K",
			98:      "EM_TPC",
			99:      "EM_SNP1K",
			100:     "EM_ST200",
			101:     "EM_IP2K",
			102:     "EM_MAX",
			103:     "EM_CR",
			104:     "EM_F2MC16",
			105:     "EM_MSP430",
			106:     "EM_BLACKFIN",
			107:     "EM_SE_C33",
			108:     "EM_SEP",
			109:     "EM_ARCA",
			110:     "EM_UNICORE",
			111:     "EM_EXCESS",
			112:     "EM_DXP",
			113:     "EM_ALTERA_NIOS2",
			114:     "EM_CRX",
			115:     "EM_XGATE",
			116:     "EM_C166",
			117:     "EM_M16C",
			118:     "EM_DSPIC30F",
			119:     "EM_CE",
			120:     "EM_M32C",
			121:     "reserved",
			122:     "reserved",
			123:     "reserved",
			124:     "reserved",
			125:     "reserved",
			126:     "reserved",
			127:     "reserved",
			128:     "reserved",
			129:     "reserved",
			130:     "reserved",
			131:     "EM_TSK3000",
			132:     "EM_RS08",
			133:     "EM_SHARC",
			134:     "EM_ECOG2",
			135:     "EM_SCORE7",
			136:     "EM_DSP24",
			137:     "EM_VIDEOCORE3",
			138:     "EM_LATTICEMICO32",
			139:     "EM_SE_C17",
			140:     "EM_TI_C6000",
			141:     "EM_TI_C2000",
			142:     "EM_TI_C5500",
			143:     "EM_TI_ARP32",
			144:     "EM_TI_PRU",
			145:     "reserved",
			160:     "EM_MMDSP_PLUS",
			161:     "EM_CYPRESS_M8C",
			162:     "EM_R32C",
			163:     "EM_TRIMEDIA",
			164:     "EM_QDSP6",
			165:     "EM_8051",
			166:     "EM_STXP7X",
			167:     "EM_NDS32",
			168:     "EM_ECOG1",
			169:     "EM_MAXQ30",
			170:     "EM_XIMO16",
			171:     "EM_MANIK",
			172:     "EM_CRAYNV2",
			173:     "EM_RX",
			174:     "EM_METAG",
			175:     "EM_MCST_ELBRUS",
			176:     "EM_ECOG16",
			177:     "EM_CR16",
			178:     "EM_ETPU",
			179:     "EM_SLE9X",
			180:     "EM_L10M",
			181:     "EM_K10M",
			182:     "reserved",
			183:     "EM_AARCH64",
			184:     "reserved",
			185:     "EM_AVR32",
			186:     "EM_STM8",
			187:     "EM_TILE64",
			188:     "EM_TILEPRO",
			189:     "EM_MICROBLAZE",
			190:     "EM_CUDA",
			191:     "EM_TILEGX",
			192:     "EM_CLOUDSHIELD",
			193:     "EM_COREA_1ST",
			194:     "EM_COREA_2ND",
			195:     "EM_ARC_COMPACT2",
			196:     "EM_OPEN8",
			197:     "EM_RL78",
			198:     "EM_VIDEOCORE5",
			199:     "EM_78KOR",
			200:     "EM_56800EX",
			201:     "EM_BA1",
			202:     "EM_BA2",
			203:     "EM_XCORE",
			204:     "EM_MCHP_PIC",
			205:     "EM_INTEL205",
			206:     "EM_INTEL206",
			207:     "EM_INTEL207",
			208:     "EM_INTEL208",
			209:     "EM_INTEL209",
			210:     "EM_KM32",
			211:     "EM_KMX32",
			212:     "EM_KMX16",
			213:     "EM_KMX8",
			214:     "EM_KVARC",
			215:     "EM_CDP",
			216:     "EM_COGE",
			217:     "EM_COOL",
			218:     "EM_NORC",
			219:     "EM_CSR_KALIMBA ",
			220:     "EM_Z80 ",
			221:     "EM_VISIUM ",
			222:     "EM_FT32 ",
			223:     "EM_MOXIE",
			224:     "EM_AMDGPU",
			225:     " ",
			243:     "EM_RISCV",
		},
		"p_type": {
			0:          "PT_NULL",
			1:          "PT_LOAD",
			2:          "PT_DYNAMIC",
			3:          "PT_INTERP",
			4:          "PT_NOTE",
			5:          "PT_SHLIB",
			6:          "PT_PHDR",
			7:          "TLS",
			0x6474e552: "GNU_RELRO",
			0x6474e551: "GNU_STACK",
			0x6ffffffa: "PT_LOSUNW",
			0x6ffffffb: "PT_SUNWBSS",
			0x6fffffff: "PT_HISUNW",
			0x70000000: "PT_LOPROC",
			0x7fffffff: "PT_HIPROC",
		},
		"p_flags": {
			0: "All access denied",
			1: "PF_X",
			2: "PF_W",
			3: "PF_W | PF_X",
			4: "PF_R",
			5: "PF_R | PF_X",
			6: "PF_R | PF_W",
			7: "PF_R + PF_W + PF_X",
		},
		"sh_type": {
			0:          "SHT_NULL",
			1:          "SHT_PROGBITS",
			2:          "SHT_SYMTAB",
			3:          "SHT_STRTAB",
			4:          "SHT_RELA",
			5:          "SHT_HASH",
			6:          "SHT_DYNAMIC",
			7:          "SHT_NOTE",
			8:          "SHT_NOBITS",
			9:          "SHT_REL",
			10:         "SHT_SHLIB",
			11:         "SHT_DYNSYM",
			0x70000000: "SHT_LOPROC",
			0x7fffffff: "SHT_HIPROC",
			0x80000000: "SHT_LOUSER",
			0xffffffff: "SHT_HIUSER",
			0x6ffffffd: "SHT_GNU_verdef",
			0x6ffffffe: "SHT_GNU_verneed",
			0x6fffffff: "SHT_GNU_versym",
		},
		"sh_flags": {},
	}
)

func main() {

	target, err := os.ReadFile("./ch2.bin")
	check_error(err)
	if !check_elf_magic(target[0:16]) {
		println("This file wasn't ELF file")
		os.Exit(0)
	}
	var elf ELF32
	elf.Ehdr.parse_Elf_header(&target[0])

	var (
		e_phoff    = int(elf.Ehdr.e_phoff)
		e_phnum    = int(elf.Ehdr.e_phnum)
		e_shnum    = int(elf.Ehdr.e_shnum)
		e_shoff    = int(elf.Ehdr.e_shoff)
		e_shstrndx = int(elf.Ehdr.e_shstrndx)
	)
	if elf.Ehdr.e_ident[4] != 1 {
		println("32 bit Only")
	}
	draw_elf_header(elf)
	fmt.Printf("Program Header : \n")

	for i := 0; i < e_phnum; i++ {
		phdr := Elf32_Phdr{}
		phdr.parse_Program_header(&target[e_phoff+SIZE_PHDR32*i])
		fmt.Printf("\tHeader_%d:\n", i)
		draw(reflect.TypeOf(&phdr), reflect.ValueOf(&phdr))
		elf.Phdr = append(elf.Phdr, phdr)
	}
	fmt.Printf("Sections Header : \n")
	for i := 0; i < e_shnum; i++ {
		shdr := Elf32_Shdr{}
		shdr.parse_Section_header(&target[e_shoff+SIZE_SHDR32*i])
		elf.Shdr = append(elf.Shdr, shdr)
	}
	for i := 0; i < e_shnum; i++ {
		shdr := elf.Shdr[i]
		strtab := unsafe.Pointer(&target[elf.Shdr[e_shstrndx].sh_offset])
		strtab = unsafe.Add(strtab, shdr.sh_name)

		for j := strtab; *(*byte)(j) != 0; j = (unsafe.Add(j, 1)) {
			fmt.Printf("%c", *(*byte)(j))
			strtab = unsafe.Add(strtab, 1)
		}
		fmt.Printf(":\n")
		draw(reflect.TypeOf(&shdr), reflect.ValueOf(&shdr))
	}
	//println(strtab)
}
func draw(key reflect.Type, value reflect.Value) {

	for j := 0; j < key.Elem().NumField(); j++ {
		v := value.Elem().Field(j).Uint()
		name := key.Elem().Field(j).Name

		if nested[name][int(v)] != "" {
			fmt.Printf("\t\t%s: %s\n", name, nested[name][int(v)])
		} else {
			fmt.Printf("\t\t%s: 0x%x\n", name, v)
		}
	}
}
func draw_elf_header(elf ELF32) {
	key := reflect.TypeOf(&elf.Ehdr)
	value := reflect.ValueOf(&elf.Ehdr)

	fmt.Printf("ELF Header : \n")
	for i := 0; i < key.Elem().NumField(); i++ {
		if i == 0 {
			fmt.Printf("\te_ident: \n")
			magic := elf.Ehdr.e_ident[0:4]
			fmt.Printf("\t\t%s: %s\n", "magic", magic)

			ei_class := elf.Ehdr.e_ident[4]
			fmt.Printf("\t\t%s: %s\n", "ei_class", nested["ei_class"][int(ei_class)])

			ei_data := elf.Ehdr.e_ident[5]
			fmt.Printf("\t\t%s: %s\n", "ei_data", nested["ei_data"][int(ei_data)])
			fmt.Printf("\t\t%s: %s\n", "ei_version", "CURRENT")

			ei_osabi := elf.Ehdr.e_ident[7]
			fmt.Printf("\t\t%s: %s\n", "ei_data", nested["ei_osabi"][int(ei_osabi)])
			fmt.Printf("\t\t.... PADDING....\n")
		} else {

			v := value.Elem().Field(i).Uint()
			name := key.Elem().Field(i).Name

			if nested[name][int(v)] != "" {
				fmt.Printf("\t%s: %s\n", name, nested[name][int(v)])
			} else {
				fmt.Printf("\t%s: 0x%x\n", name, v)
			}

		}
	}
}
