#include <defs.h>
#include "gcore_defs.h"

static void
elf64_fill_elf_header(struct gcore_elf_struct *this, uint16_t e_phnum,
		      uint16_t e_machine, uint32_t e_flags, uint8_t ei_osabi)
{
	Elf64_Ehdr *e = &this->elf64.ehdr;

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
	Elf64_Shdr *s = &this->elf64.shdr;

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
	Elf64_Phdr *p = &this->elf64.phdr;

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
	Elf64_Nhdr *n = &this->elf64.nhdr;

	BZERO(n, sizeof(*n));

	n->n_namesz = n_namesz;
	n->n_descsz = n_descsz;
	n->n_type = n_type;
}

static int elf64_write_elf_header(struct gcore_elf_struct *this, int fd)
{
	Elf64_Ehdr *e = &this->elf64.ehdr;

	if (write(fd, e, sizeof(*e)) != sizeof(*e))
		return FALSE;

	return TRUE;
}

static int elf64_write_section_header(struct gcore_elf_struct *this, int fd)
{
	Elf64_Shdr *s = &this->elf64.shdr;

	if (write(fd, s, sizeof(*s)) != sizeof(*s))
		return FALSE;

	return TRUE;
}

static int elf64_write_program_header(struct gcore_elf_struct *this, int fd)
{
	Elf64_Phdr *p = &this->elf64.phdr;

	if (write(fd, p, sizeof(*p)) != sizeof(*p))
		return FALSE;

	return TRUE;
}

static int elf64_write_note_header(struct gcore_elf_struct *this, int fd,
				   off_t *offset)
{
	Elf64_Nhdr *n = &this->elf64.nhdr;

	if (write(fd, n, sizeof(*n)) != sizeof(*n))
		return FALSE;

	*offset += sizeof(*n);

	return TRUE;
}

static uint64_t elf64_get_e_shoff(struct gcore_elf_struct *this)
{
	return this->elf64.ehdr.e_shoff;
}

static uint16_t elf64_get_e_ehsize(struct gcore_elf_struct *this)
{
	return this->elf64.ehdr.e_ehsize;
}

static uint16_t elf64_get_e_phentsize(struct gcore_elf_struct *this)
{
	return this->elf64.ehdr.e_phentsize;
}

static uint16_t elf64_get_e_shentsize(struct gcore_elf_struct *this)
{
	return this->elf64.ehdr.e_shentsize;
}

static uint16_t elf64_get_e_shnum(struct gcore_elf_struct *this)
{
	return this->elf64.ehdr.e_shnum;
}

static size_t elf64_get_note_header_size(struct gcore_elf_struct *this)
{
	return sizeof(this->elf64.nhdr);
}

static struct gcore_elf_operations elf64_ops =
{
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
	.get_e_shentsize = elf64_get_e_shentsize,
	.get_e_shnum = elf64_get_e_shnum,
	.get_note_header_size = elf64_get_note_header_size
};

static void
elf32_fill_elf_header(struct gcore_elf_struct *this, uint16_t e_phnum,
		      uint16_t e_machine, uint32_t e_flags, uint8_t ei_osabi)
{
	Elf32_Ehdr *e = &this->elf32.ehdr;

	BZERO(e, sizeof(*e));

	BCOPY(ELFMAG, e->e_ident, SELFMAG);
	e->e_ident[EI_CLASS] = ELFCLASS32;
	e->e_ident[EI_DATA] = ELFDATA2LSB;
	e->e_ident[EI_VERSION] = EV_CURRENT;
	e->e_ident[EI_OSABI] = ei_osabi;
	e->e_ehsize = sizeof(Elf32_Ehdr);
	e->e_phentsize = sizeof(Elf32_Phdr);
	e->e_phnum = e_phnum;
	e->e_type = ET_CORE;
	e->e_machine = e_machine;
	e->e_version = EV_CURRENT;
	e->e_phoff = e->e_ehsize + e->e_shentsize * e->e_shnum;
	e->e_flags = e_flags;
}

static void
elf32_fill_section_header(struct gcore_elf_struct *this, int phnum)
{
	Elf32_Shdr *s = &this->elf32.shdr;

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
	Elf32_Phdr *p = &this->elf32.phdr;

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
	Elf32_Nhdr *n = &this->elf32.nhdr;

	BZERO(n, sizeof(*n));

	n->n_namesz = n_namesz;
	n->n_descsz = n_descsz;
	n->n_type = n_type;
}

static int elf32_write_elf_header(struct gcore_elf_struct *this, int fd)
{
	Elf32_Ehdr *e = &this->elf32.ehdr;

	if (write(fd, e, sizeof(*e)) != sizeof(*e))
		return FALSE;

	return TRUE;
}

static int elf32_write_section_header(struct gcore_elf_struct *this, int fd)
{
	Elf32_Shdr *s = &this->elf32.shdr;

	if (write(fd, s, sizeof(*s)) != sizeof(*s))
		return FALSE;

	return TRUE;
}

static int elf32_write_program_header(struct gcore_elf_struct *this, int fd)
{
	Elf32_Phdr *p = &this->elf32.phdr;

	if (write(fd, p, sizeof(*p)) != sizeof(*p))
		return FALSE;

	return TRUE;
}

static int elf32_write_note_header(struct gcore_elf_struct *this, int fd,
				   off_t *offset)
{
	Elf32_Nhdr *n = &this->elf32.nhdr;

	if (write(fd, n, sizeof(*n)) != sizeof(*n))
		return FALSE;

	*offset += sizeof(*n);

	return TRUE;
}

static uint64_t elf32_get_e_shoff(struct gcore_elf_struct *this)
{
	return this->elf32.ehdr.e_shoff;
}

static uint16_t elf32_get_e_ehsize(struct gcore_elf_struct *this)
{
	return this->elf32.ehdr.e_ehsize;
}

static uint16_t elf32_get_e_phentsize(struct gcore_elf_struct *this)
{
	return this->elf32.ehdr.e_phentsize;
}

static uint16_t elf32_get_e_shentsize(struct gcore_elf_struct *this)
{
	return this->elf32.ehdr.e_shentsize;
}

static uint16_t elf32_get_e_shnum(struct gcore_elf_struct *this)
{
	return this->elf32.ehdr.e_shnum;
}

static size_t elf32_get_note_header_size(struct gcore_elf_struct *this)
{
	return sizeof(this->elf32.nhdr);
}

static struct gcore_elf_operations elf32_ops =
{
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
	.get_e_shentsize = elf32_get_e_shentsize,
	.get_e_shnum = elf32_get_e_shnum,
	.get_note_header_size = elf32_get_note_header_size
};

void gcore_elf_set_operations(struct gcore_elf_struct *this)
{
	this->ops = BITS32() ? &elf32_ops : &elf64_ops;
}
