#include <defs.h>
#include "gcore_defs.h"

struct gcore_elf64_struct
{
	struct gcore_elf_struct super;
	Elf64_Ehdr ehdr;
	Elf64_Shdr shdr;
	Elf64_Phdr phdr;
	Elf64_Nhdr nhdr;
};

struct gcore_elf32_struct
{
	struct gcore_elf_struct super;
	Elf32_Ehdr ehdr;
	Elf32_Shdr shdr;
	Elf32_Phdr phdr;
	Elf32_Nhdr nhdr;
};

static void
elf64_fill_elf_header(struct gcore_elf_struct *this, uint16_t e_phnum,
		      uint16_t e_machine, uint32_t e_flags, uint8_t ei_osabi)
{
	Elf64_Ehdr *e = &((struct gcore_elf64_struct *)this)->ehdr;

	BZERO(e, sizeof(*e));

	BCOPY(ELFMAG, e->e_ident, SELFMAG);
	e->e_ident[EI_CLASS] = ELFCLASS64;
	e->e_ident[EI_DATA] = ELFDATA2LSB;
	e->e_ident[EI_VERSION] = EV_CURRENT;
	e->e_ident[EI_OSABI] = ei_osabi;
	e->e_ehsize = sizeof(Elf64_Ehdr);
	e->e_phentsize = sizeof(Elf64_Phdr);
	e->e_phnum = e_phnum >= PN_XNUM ? PN_XNUM : e_phnum;
	e->e_type = ET_CORE;
	e->e_machine = e_machine;
	e->e_version = EV_CURRENT;
	e->e_phoff = e->e_ehsize + e->e_shentsize * e->e_shnum;
	e->e_flags = e_flags;
}

static void
elf64_fill_section_header(struct gcore_elf_struct *this, int phnum)
{
	Elf64_Shdr *s = &((struct gcore_elf64_struct *)this)->shdr;

	BZERO(s, sizeof(*s));

	s->sh_type = SHT_NULL;
	s->sh_size = 1;
	s->sh_link = SHN_UNDEF;
	s->sh_info = phnum;
}

static void
elf64_fill_program_header(struct gcore_elf_struct *this, uint32_t p_type,
			  uint32_t p_flags, uint64_t p_offset,
			  uint64_t p_vaddr, uint64_t p_filesz,
			  uint64_t p_memsz, uint64_t p_align)
{
	Elf64_Phdr *p = &((struct gcore_elf64_struct *)this)->phdr;

	BZERO(p, sizeof(*p));

	p->p_type = p_type;
	p->p_flags = p_flags;
	p->p_offset = p_offset;
	p->p_vaddr = p_vaddr;
	p->p_filesz = p_filesz;
	p->p_memsz = p_memsz;
	p->p_align = p_align;
}

static void
elf64_fill_note_header(struct gcore_elf_struct *this, uint32_t n_namesz,
		       uint32_t n_descsz, uint32_t n_type)
{
	Elf64_Nhdr *n = &((struct gcore_elf64_struct *)this)->nhdr;

	BZERO(n, sizeof(*n));

	n->n_namesz = n_namesz;
	n->n_descsz = n_descsz;
	n->n_type = n_type;
}

static int elf64_write_elf_header(struct gcore_elf_struct *this, int fd)
{
	Elf64_Ehdr *e = &((struct gcore_elf64_struct *)this)->ehdr;

	if (write(fd, e, sizeof(*e)) != sizeof(*e))
		return FALSE;

	return TRUE;
}

static int elf64_write_section_header(struct gcore_elf_struct *this, int fd)
{
	Elf64_Shdr *s = &((struct gcore_elf64_struct *)this)->shdr;

	if (write(fd, s, sizeof(*s)) != sizeof(*s))
		return FALSE;

	return TRUE;
}

static int elf64_write_program_header(struct gcore_elf_struct *this, int fd)
{
	Elf64_Phdr *p = &((struct gcore_elf64_struct *)this)->phdr;

	if (write(fd, p, sizeof(*p)) != sizeof(*p))
		return FALSE;

	return TRUE;
}

static int elf64_write_note_header(struct gcore_elf_struct *this, int fd,
				   off_t *offset)
{
	Elf64_Nhdr *n = &((struct gcore_elf64_struct *)this)->nhdr;

	if (write(fd, n, sizeof(*n)) != sizeof(*n))
		return FALSE;

	*offset += sizeof(*n);

	return TRUE;
}

static uint64_t elf64_get_e_shoff(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf64_struct *)this)->ehdr.e_shoff;
}

static uint16_t elf64_get_e_ehsize(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf64_struct *)this)->ehdr.e_ehsize;
}

static uint16_t elf64_get_e_phentsize(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf64_struct *)this)->ehdr.e_phentsize;
}

static uint16_t elf64_get_e_phnum(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf64_struct *)this)->ehdr.e_phnum;
}

static uint16_t elf64_get_e_shentsize(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf64_struct *)this)->ehdr.e_shentsize;
}

static uint16_t elf64_get_e_shnum(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf64_struct *)this)->ehdr.e_shnum;
}

static uint32_t elf64_get_sh_info(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf64_struct *)this)->shdr.sh_info;
}

static size_t elf64_get_note_header_size(struct gcore_elf_struct *this)
{
	return sizeof(((struct gcore_elf64_struct *)this)->nhdr);
}

struct gcore_elf_operations gcore_elf64_operations = {
	.fill_elf_header = elf64_fill_elf_header,
	.fill_section_header = elf64_fill_section_header,
	.fill_program_header = elf64_fill_program_header,
	.fill_note_header = elf64_fill_note_header,

	.write_elf_header = elf64_write_elf_header,
	.write_section_header = elf64_write_section_header,
	.write_program_header = elf64_write_program_header,
	.write_note_header = elf64_write_note_header,

	.get_e_shoff = elf64_get_e_shoff,
	.get_e_ehsize = elf64_get_e_ehsize,
	.get_e_phentsize = elf64_get_e_phentsize,
	.get_e_phnum = elf64_get_e_phnum,
	.get_e_shentsize = elf64_get_e_shentsize,
	.get_e_shnum = elf64_get_e_shnum,

	.get_sh_info = elf64_get_sh_info,

	.get_note_header_size = elf64_get_note_header_size,
};

const struct gcore_elf_operations *gcore_elf64_get_operations(void)
{
	return &gcore_elf64_operations;
}

static void
elf32_fill_elf_header(struct gcore_elf_struct *this, uint16_t e_phnum,
		      uint16_t e_machine, uint32_t e_flags, uint8_t ei_osabi)
{
	Elf32_Ehdr *e = &((struct gcore_elf32_struct *)this)->ehdr;

	BZERO(e, sizeof(*e));

	BCOPY(ELFMAG, e->e_ident, SELFMAG);
	e->e_ident[EI_CLASS] = ELFCLASS32;
	e->e_ident[EI_DATA] = ELFDATA2LSB;
	e->e_ident[EI_VERSION] = EV_CURRENT;
	e->e_ident[EI_OSABI] = ei_osabi;
	e->e_ehsize = sizeof(Elf32_Ehdr);
	e->e_phentsize = sizeof(Elf32_Phdr);
	e->e_phnum = e_phnum >= PN_XNUM ? PN_XNUM : e_phnum;
	e->e_type = ET_CORE;
	e->e_machine = e_machine;
	e->e_version = EV_CURRENT;
	e->e_phoff = e->e_ehsize + e->e_shentsize * e->e_shnum;
	e->e_flags = e_flags;
}

static void
elf32_fill_section_header(struct gcore_elf_struct *this, int phnum)
{
	Elf32_Shdr *s = &((struct gcore_elf32_struct *)this)->shdr;

	BZERO(s, sizeof(*s));

	s->sh_type = SHT_NULL;
	s->sh_size = 1;
	s->sh_link = SHN_UNDEF;
	s->sh_info = phnum;
}

static void
elf32_fill_program_header(struct gcore_elf_struct *this, uint32_t p_type,
			  uint32_t p_flags, uint64_t p_offset,
			  uint64_t p_vaddr, uint64_t p_filesz,
			  uint64_t p_memsz, uint64_t p_align)
{
	Elf32_Phdr *p = &((struct gcore_elf32_struct *)this)->phdr;

	BZERO(p, sizeof(*p));

	p->p_type = p_type;
	p->p_flags = p_flags;
	p->p_offset = p_offset;
	p->p_vaddr = p_vaddr;
	p->p_filesz = p_filesz;
	p->p_memsz = p_memsz;
	p->p_align = p_align;
}

static void
elf32_fill_note_header(struct gcore_elf_struct *this, uint32_t n_namesz,
		       uint32_t n_descsz, uint32_t n_type)
{
	Elf32_Nhdr *n = &((struct gcore_elf32_struct *)this)->nhdr;

	BZERO(n, sizeof(*n));

	n->n_namesz = n_namesz;
	n->n_descsz = n_descsz;
	n->n_type = n_type;
}

static int elf32_write_elf_header(struct gcore_elf_struct *this, int fd)
{
	Elf32_Ehdr *e = &((struct gcore_elf32_struct *)this)->ehdr;

	if (write(fd, e, sizeof(*e)) != sizeof(*e))
		return FALSE;

	return TRUE;
}

static int elf32_write_section_header(struct gcore_elf_struct *this, int fd)
{
	Elf32_Shdr *s = &((struct gcore_elf32_struct *)this)->shdr;

	if (write(fd, s, sizeof(*s)) != sizeof(*s))
		return FALSE;

	return TRUE;
}

static int elf32_write_program_header(struct gcore_elf_struct *this, int fd)
{
	Elf32_Phdr *p = &((struct gcore_elf32_struct *)this)->phdr;

	if (write(fd, p, sizeof(*p)) != sizeof(*p))
		return FALSE;

	return TRUE;
}

static int elf32_write_note_header(struct gcore_elf_struct *this, int fd,
				   off_t *offset)
{
	Elf32_Nhdr *n = &((struct gcore_elf32_struct *)this)->nhdr;

	if (write(fd, n, sizeof(*n)) != sizeof(*n))
		return FALSE;

	*offset += sizeof(*n);

	return TRUE;
}

static uint64_t elf32_get_e_shoff(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf32_struct *)this)->ehdr.e_shoff;
}

static uint16_t elf32_get_e_ehsize(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf32_struct *)this)->ehdr.e_ehsize;
}

static uint16_t elf32_get_e_phentsize(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf32_struct *)this)->ehdr.e_phentsize;
}

static uint16_t elf32_get_e_phnum(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf32_struct *)this)->ehdr.e_phnum;
}

static uint16_t elf32_get_e_shentsize(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf32_struct *)this)->ehdr.e_shentsize;
}

static uint16_t elf32_get_e_shnum(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf32_struct *)this)->ehdr.e_shnum;
}

static uint32_t elf32_get_sh_info(struct gcore_elf_struct *this)
{
	return ((struct gcore_elf32_struct *)this)->shdr.sh_info;
}

static size_t elf32_get_note_header_size(struct gcore_elf_struct *this)
{
	return sizeof(((struct gcore_elf32_struct *)this)->nhdr);
}

struct gcore_elf_operations gcore_elf32_operations = {
	.fill_elf_header = elf32_fill_elf_header,
	.fill_section_header = elf32_fill_section_header,
	.fill_program_header = elf32_fill_program_header,
	.fill_note_header = elf32_fill_note_header,

	.write_elf_header = elf32_write_elf_header,
	.write_section_header = elf32_write_section_header,
	.write_program_header = elf32_write_program_header,
	.write_note_header = elf32_write_note_header,

	.get_e_shoff = elf32_get_e_shoff,
	.get_e_ehsize = elf32_get_e_ehsize,
	.get_e_phentsize = elf32_get_e_phentsize,
	.get_e_phnum = elf32_get_e_phnum,
	.get_e_shentsize = elf32_get_e_shentsize,
	.get_e_shnum = elf32_get_e_shnum,

	.get_sh_info = elf32_get_sh_info,

	.get_note_header_size = elf32_get_note_header_size,
};

const struct gcore_elf_operations *gcore_elf32_get_operations(void)
{
	return &gcore_elf32_operations;
}

/**
 * Initilize ELF interface. Choose an appropreate operation by looking
 * at a bit length of the current execution environment and 32bit
 * emulation. Allocate a enough memory space for a chosen
 * struct. Insert NULL into the unchoosed field.
 *
 * Assume invoked at the beginning of dump processing.
 */
void gcore_elf_init(struct gcore_one_session_data *gcore)
{
	size_t size;
	struct gcore_elf_operations *ops;

	if (BITS32() || gcore_is_arch_32bit_emulation(CURRENT_CONTEXT())) {
		size = sizeof(struct gcore_elf32_struct);
		ops = &gcore_elf32_operations;
	} else {
		size = sizeof(struct gcore_elf64_struct);
		ops = &gcore_elf64_operations;
	}

	gcore->elf = (struct gcore_elf_struct *)GETBUF(size);
	BZERO(gcore->elf, size);
	gcore->elf->ops = ops;
}
