/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __ON_LLC_MISS_BPF_SKEL_H__
#define __ON_LLC_MISS_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define BPF_SKEL_SUPPORTS_MAP_AUTO_ATTACH 1

struct on_llc_miss_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *stacks;
		struct bpf_map *events;
	} maps;
	struct {
		struct bpf_program *on_cache_miss;
	} progs;
	struct {
		struct bpf_link *on_cache_miss;
	} links;

#ifdef __cplusplus
	static inline struct on_llc_miss_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct on_llc_miss_bpf *open_and_load();
	static inline int load(struct on_llc_miss_bpf *skel);
	static inline int attach(struct on_llc_miss_bpf *skel);
	static inline void detach(struct on_llc_miss_bpf *skel);
	static inline void destroy(struct on_llc_miss_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
on_llc_miss_bpf__destroy(struct on_llc_miss_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
on_llc_miss_bpf__create_skeleton(struct on_llc_miss_bpf *obj);

static inline struct on_llc_miss_bpf *
on_llc_miss_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct on_llc_miss_bpf *obj;
	int err;

	obj = (struct on_llc_miss_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = on_llc_miss_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	on_llc_miss_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct on_llc_miss_bpf *
on_llc_miss_bpf__open(void)
{
	return on_llc_miss_bpf__open_opts(NULL);
}

static inline int
on_llc_miss_bpf__load(struct on_llc_miss_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct on_llc_miss_bpf *
on_llc_miss_bpf__open_and_load(void)
{
	struct on_llc_miss_bpf *obj;
	int err;

	obj = on_llc_miss_bpf__open();
	if (!obj)
		return NULL;
	err = on_llc_miss_bpf__load(obj);
	if (err) {
		on_llc_miss_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
on_llc_miss_bpf__attach(struct on_llc_miss_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
on_llc_miss_bpf__detach(struct on_llc_miss_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *on_llc_miss_bpf__elf_bytes(size_t *sz);

static inline int
on_llc_miss_bpf__create_skeleton(struct on_llc_miss_bpf *obj)
{
	struct bpf_object_skeleton *s;
	struct bpf_map_skeleton *map __attribute__((unused));
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "on_llc_miss_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = 24;
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt,
			sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
	map->name = "stacks";
	map->map = &obj->maps.stacks;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 1 * s->map_skel_sz);
	map->name = "events";
	map->map = &obj->maps.events;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "on_cache_miss";
	s->progs[0].prog = &obj->progs.on_cache_miss;
	s->progs[0].link = &obj->links.on_cache_miss;

	s->data = on_llc_miss_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *on_llc_miss_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xd8\x12\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1b\0\
\x01\0\xbf\x16\0\0\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x03\0\0\0\
\x05\0\0\x85\0\0\0\x1b\0\0\0\xbf\x01\0\0\0\0\0\0\xb7\0\0\0\x01\0\0\0\x7b\x1a\
\xf8\xff\0\0\0\0\x15\x01\x0a\0\0\0\0\0\xbf\xa4\0\0\0\0\0\0\x07\x04\0\0\xf8\xff\
\xff\xff\xbf\x61\0\0\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x03\0\0\
\xff\xff\xff\xff\0\0\0\0\0\0\0\0\xb7\x05\0\0\x08\0\0\0\x85\0\0\0\x19\0\0\0\xb7\
\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x47\x50\x4c\
\0\x2a\0\0\0\x05\0\x08\0\x02\0\0\0\x08\0\0\0\x14\0\0\0\x04\0\x08\x01\x51\x04\
\x08\xa0\x01\x01\x56\0\x04\x08\x40\x02\x30\x9f\x04\x40\xa0\x01\x02\x7a\0\0\x01\
\x11\x01\x25\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\
\x17\x8c\x01\x17\0\0\x02\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\0\0\x03\x26\0\
\x49\x13\0\0\x04\x0f\0\x49\x13\0\0\x05\x15\x01\x49\x13\x27\x19\0\0\x06\x05\0\
\x49\x13\0\0\x07\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\x08\x0f\0\0\0\x09\x16\0\x49\
\x13\x03\x25\x3a\x0b\x3b\x05\0\0\x0a\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\
\x0b\x02\x18\0\0\x0b\x01\x01\x49\x13\0\0\x0c\x21\0\x49\x13\x37\x0b\0\0\x0d\x24\
\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x0e\x13\x01\x0b\x0b\x3a\x0b\x3b\x0b\0\0\x0f\x0d\
\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\x10\x21\0\x49\x13\x37\x05\0\0\
\x11\x04\x01\x49\x13\x0b\x0b\x3a\x0b\x3b\x05\0\0\x12\x28\0\x03\x25\x1c\x0f\0\0\
\x13\x2e\x01\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\x19\
\x49\x13\x3f\x19\0\0\x14\x05\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x15\
\x34\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x16\x13\x01\x03\x25\x0b\x0b\
\x3a\x0b\x3b\x0b\0\0\0\xd0\x01\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x1d\0\x01\x08\0\
\0\0\0\0\0\0\x02\x03\xa0\0\0\0\x08\0\0\0\x0c\0\0\0\x02\x03\x30\0\0\0\x02\x05\
\x03\x03\x35\0\0\0\x04\x3a\0\0\0\x05\x4f\0\0\0\x06\x53\0\0\0\x06\x53\0\0\0\x06\
\x54\0\0\0\0\x07\x04\x05\x08\x08\x09\x5d\0\0\0\x06\x01\x87\x67\x07\x05\x07\x08\
\x02\x07\x6a\0\0\0\x02\xc2\x02\x03\x6f\0\0\0\x04\x74\0\0\0\x05\x4f\0\0\0\x06\
\x53\0\0\0\x06\x53\0\0\0\x06\x54\0\0\0\x06\x53\0\0\0\x06\x54\0\0\0\0\x0a\x08\
\x9e\0\0\0\0\x25\x02\xa1\0\x0b\xaa\0\0\0\x0c\xae\0\0\0\x04\0\x07\x09\x06\x01\
\x0d\x0a\x08\x07\x0a\x0b\xbd\0\0\0\0\x0d\x02\xa1\x01\x0e\x20\0\x08\x0f\x0c\xe6\
\0\0\0\0\x09\0\x0f\x0e\xfb\0\0\0\0\x0a\x08\x0f\x0f\x0d\x01\0\0\0\x0b\x10\x0f\
\x10\x1e\x01\0\0\0\x0c\x18\0\x04\xeb\0\0\0\x0b\xf7\0\0\0\x0c\xae\0\0\0\x07\0\
\x07\x0d\x05\x04\x04\0\x01\0\0\x0b\xf7\0\0\0\x10\xae\0\0\0\0\x10\0\x04\x12\x01\
\0\0\x0b\xf7\0\0\0\x0c\xae\0\0\0\x04\0\x04\x23\x01\0\0\x0b\xf7\0\0\0\x0c\xae\0\
\0\0\x50\0\x0a\x11\x3a\x01\0\0\0\x13\x02\xa1\x02\x0e\x18\0\x0f\x0f\x0c\x0d\x01\
\0\0\0\x10\0\x0f\x0f\x0d\x01\0\0\0\x11\x08\x0f\x10\x0d\x01\0\0\0\x12\x10\0\x11\
\x78\x01\0\0\x04\x01\x86\x03\x12\x13\xff\x01\x12\x14\x80\x02\x12\x15\x80\x04\
\x12\x16\x80\x08\x12\x17\x80\x10\0\x07\x12\x07\x04\x11\x9e\x01\0\0\x08\x01\x4f\
\x03\x12\x19\xff\xff\xff\xff\x0f\x12\x1a\xff\xff\xff\xff\x0f\x12\x1b\x80\x80\
\x80\x80\xf0\xff\xff\x07\0\x07\x18\x07\x08\x13\x03\xa0\0\0\0\x01\x5a\x1c\0\x16\
\xf7\0\0\0\x14\0\x1d\0\x16\x53\0\0\0\x15\x01\x1e\0\x17\xc4\x01\0\0\0\x16\x20\
\x08\x03\x01\x0f\x1f\x9e\x01\0\0\x03\x02\0\0\0\x88\0\0\0\x05\0\0\0\0\0\0\0\x15\
\0\0\0\x27\0\0\0\x50\0\0\0\x60\0\0\0\x65\0\0\0\x78\0\0\0\x7e\0\0\0\x94\0\0\0\
\x9c\0\0\0\xa1\0\0\0\xb5\0\0\0\xbc\0\0\0\xc1\0\0\0\xc5\0\0\0\xd1\0\0\0\xda\0\0\
\0\xe5\0\0\0\xec\0\0\0\xf9\0\0\0\x0f\x01\0\0\x20\x01\0\0\x35\x01\0\0\x49\x01\0\
\0\x5d\x01\0\0\x6b\x01\0\0\x7c\x01\0\0\x8e\x01\0\0\xa0\x01\0\0\xae\x01\0\0\xb2\
\x01\0\0\xba\x01\0\0\xc3\x01\0\0\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\
\x6f\x6e\x20\x31\x39\x2e\x31\x2e\x36\0\x6f\x6e\x5f\x6c\x6c\x63\x5f\x6d\x69\x73\
\x73\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x72\x63\x69\x6e\
\x2f\x44\x6f\x6b\x75\x6d\x65\x6e\x74\x79\x2f\x62\x70\x66\x2f\x6f\x6e\x5f\x6c\
\x6c\x63\x5f\x6d\x69\x73\x73\x2f\x33\0\x62\x70\x66\x5f\x67\x65\x74\x5f\x73\x74\
\x61\x63\x6b\x69\x64\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\
\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x36\x34\0\x62\x70\x66\x5f\
\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\x74\x5f\x6f\x75\x74\x70\x75\x74\0\x4c\x49\
\x43\x45\x4e\x53\x45\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\
\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x73\x74\x61\x63\x6b\x73\0\x74\x79\
\x70\x65\0\x69\x6e\x74\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x65\
\x79\x5f\x73\x69\x7a\x65\0\x76\x61\x6c\x75\x65\x5f\x73\x69\x7a\x65\0\x65\x76\
\x65\x6e\x74\x73\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x42\x50\
\x46\x5f\x46\x5f\x53\x4b\x49\x50\x5f\x46\x49\x45\x4c\x44\x5f\x4d\x41\x53\x4b\0\
\x42\x50\x46\x5f\x46\x5f\x55\x53\x45\x52\x5f\x53\x54\x41\x43\x4b\0\x42\x50\x46\
\x5f\x46\x5f\x46\x41\x53\x54\x5f\x53\x54\x41\x43\x4b\x5f\x43\x4d\x50\0\x42\x50\
\x46\x5f\x46\x5f\x52\x45\x55\x53\x45\x5f\x53\x54\x41\x43\x4b\x49\x44\0\x42\x50\
\x46\x5f\x46\x5f\x55\x53\x45\x52\x5f\x42\x55\x49\x4c\x44\x5f\x49\x44\0\x75\x6e\
\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x42\x50\x46\x5f\x46\x5f\x49\x4e\
\x44\x45\x58\x5f\x4d\x41\x53\x4b\0\x42\x50\x46\x5f\x46\x5f\x43\x55\x52\x52\x45\
\x4e\x54\x5f\x43\x50\x55\0\x42\x50\x46\x5f\x46\x5f\x43\x54\x58\x4c\x45\x4e\x5f\
\x4d\x41\x53\x4b\0\x6f\x6e\x5f\x63\x61\x63\x68\x65\x5f\x6d\x69\x73\x73\0\x63\
\x74\x78\0\x70\x61\x79\x6c\x6f\x61\x64\0\x73\x74\x61\x63\x6b\x5f\x69\x64\0\x65\
\x76\x65\x6e\x74\0\x24\0\0\0\x05\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\xdc\x01\0\0\xdc\
\x01\0\0\xa0\x01\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x07\0\0\0\x05\0\0\0\
\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\
\0\0\0\x02\0\0\0\x04\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\0\0\0\0\
\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\
\x19\0\0\0\x01\0\0\0\0\0\0\0\x1e\0\0\0\x05\0\0\0\x40\0\0\0\x2a\0\0\0\x07\0\0\0\
\x80\0\0\0\x33\0\0\0\x09\0\0\0\xc0\0\0\0\x3e\0\0\0\0\0\0\x0e\x0b\0\0\0\x01\0\0\
\0\0\0\0\0\x03\0\0\x04\x18\0\0\0\x19\0\0\0\x07\0\0\0\0\0\0\0\x2a\0\0\0\x07\0\0\
\0\x40\0\0\0\x33\0\0\0\x07\0\0\0\x80\0\0\0\x45\0\0\0\0\0\0\x0e\x0d\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x4c\0\0\0\x0f\0\0\
\0\x50\0\0\0\x01\0\0\x0c\x10\0\0\0\x85\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\
\0\0\0\0\0\0\0\x03\0\0\0\0\x12\0\0\0\x04\0\0\0\x04\0\0\0\x8a\x01\0\0\0\0\0\x0e\
\x13\0\0\0\x01\0\0\0\x92\x01\0\0\x02\0\0\x0f\0\0\0\0\x0c\0\0\0\0\0\0\0\x20\0\0\
\0\x0e\0\0\0\0\0\0\0\x18\0\0\0\x98\x01\0\0\x01\0\0\x0f\0\0\0\0\x14\0\0\0\0\0\0\
\0\x04\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\
\x5f\x54\x59\x50\x45\x5f\x5f\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\
\x72\x69\x65\x73\0\x6b\x65\x79\x5f\x73\x69\x7a\x65\0\x76\x61\x6c\x75\x65\x5f\
\x73\x69\x7a\x65\0\x73\x74\x61\x63\x6b\x73\0\x65\x76\x65\x6e\x74\x73\0\x63\x74\
\x78\0\x6f\x6e\x5f\x63\x61\x63\x68\x65\x5f\x6d\x69\x73\x73\0\x70\x65\x72\x66\
\x5f\x65\x76\x65\x6e\x74\0\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x72\x63\x69\x6e\x2f\
\x44\x6f\x6b\x75\x6d\x65\x6e\x74\x79\x2f\x62\x70\x66\x2f\x6f\x6e\x5f\x6c\x6c\
\x63\x5f\x6d\x69\x73\x73\x2f\x33\x2f\x6f\x6e\x5f\x6c\x6c\x63\x5f\x6d\x69\x73\
\x73\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x6f\x6e\x5f\x63\x61\x63\x68\x65\
\x5f\x6d\x69\x73\x73\x28\x76\x6f\x69\x64\x20\x2a\x63\x74\x78\x29\x20\x7b\0\x20\
\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x73\x74\x61\x63\x6b\x69\
\x64\x28\x63\x74\x78\x2c\x20\x26\x73\x74\x61\x63\x6b\x73\x2c\x20\x42\x50\x46\
\x5f\x46\x5f\x55\x53\x45\x52\x5f\x53\x54\x41\x43\x4b\x20\x7c\x20\x42\x50\x46\
\x5f\x46\x5f\x52\x45\x55\x53\x45\x5f\x53\x54\x41\x43\x4b\x49\x44\x29\x3b\0\x20\
\x20\x70\x61\x79\x6c\x6f\x61\x64\x2e\x73\x74\x61\x63\x6b\x5f\x69\x64\x20\x3d\0\
\x20\x20\x69\x66\x20\x28\x21\x70\x61\x79\x6c\x6f\x61\x64\x2e\x73\x74\x61\x63\
\x6b\x5f\x69\x64\x29\x20\x7b\0\x20\x20\x62\x70\x66\x5f\x70\x65\x72\x66\x5f\x65\
\x76\x65\x6e\x74\x5f\x6f\x75\x74\x70\x75\x74\x28\x63\x74\x78\x2c\x20\x26\x65\
\x76\x65\x6e\x74\x73\x2c\x20\x42\x50\x46\x5f\x46\x5f\x43\x55\x52\x52\x45\x4e\
\x54\x5f\x43\x50\x55\x2c\x20\x26\x70\x61\x79\x6c\x6f\x61\x64\x2c\0\x7d\0\x63\
\x68\x61\x72\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\x6d\x61\x70\x73\0\x6c\x69\x63\
\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x6c\0\0\
\0\x80\0\0\0\0\0\0\0\x08\0\0\0\x5e\0\0\0\x01\0\0\0\0\0\0\0\x11\0\0\0\x10\0\0\0\
\x5e\0\0\0\x06\0\0\0\0\0\0\0\x69\0\0\0\xa4\0\0\0\0\x58\0\0\x08\0\0\0\x69\0\0\0\
\xc3\0\0\0\x07\x68\0\0\x38\0\0\0\x69\0\0\0\x10\x01\0\0\x14\x64\0\0\x40\0\0\0\
\x69\0\0\0\x25\x01\0\0\x07\x70\0\0\x58\0\0\0\x69\0\0\0\x40\x01\0\0\x03\x80\0\0\
\x98\0\0\0\x69\0\0\0\x83\x01\0\0\x01\x8c\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\
\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\
\xb9\0\0\0\x05\0\x08\0\x7e\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\
\0\x01\0\0\x01\x01\x01\x1f\x03\0\0\0\0\x29\0\0\0\x2b\0\0\0\x03\x01\x1f\x02\x0f\
\x05\x1e\x04\x3c\0\0\0\0\xec\xe4\xca\0\x6e\xe3\x92\x53\xb4\x0f\xd6\x3c\x82\xea\
\x9a\xba\x4e\0\0\0\x01\x02\xd0\x2d\xcb\x4f\x69\x27\x6e\x04\xad\x3d\xcb\xa0\xa1\
\xa5\xb8\x5c\0\0\0\x02\xa5\xa8\xa4\xf9\x34\xaa\x57\x11\xde\xc2\x3f\xec\x64\x5c\
\x40\x01\x6e\0\0\0\x01\x4e\xbf\xf7\xec\xda\xce\xf1\x79\xb3\xde\xb9\xfe\x5a\x15\
\x1f\x7c\x04\0\0\x09\x02\0\0\0\0\0\0\0\0\x03\x15\x01\x05\x07\x0a\x24\x05\x14\
\x65\x05\x07\x23\x06\x03\x64\x20\x05\x03\x06\x03\x20\x2e\x06\x03\x60\x74\x05\
\x01\x06\x03\x23\x20\x02\x01\0\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x72\x63\
\x69\x6e\x2f\x44\x6f\x6b\x75\x6d\x65\x6e\x74\x79\x2f\x62\x70\x66\x2f\x6f\x6e\
\x5f\x6c\x6c\x63\x5f\x6d\x69\x73\x73\x2f\x33\0\x2e\0\x2f\x75\x73\x72\x2f\x69\
\x6e\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\0\x6f\x6e\x5f\x6c\x6c\x63\x5f\x6d\x69\
\x73\x73\x2e\x62\x70\x66\x2e\x63\0\x76\x6d\x6c\x69\x6e\x75\x78\x2e\x68\x2e\x62\
\x61\x6b\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\
\0\x6f\x6e\x5f\x6c\x6c\x63\x5f\x6d\x69\x73\x73\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xec\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x16\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x18\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x5f\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\x73\
\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x41\0\0\0\x11\0\x05\0\x20\
\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x17\x01\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x04\0\
\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x01\0\0\0\x0c\0\0\0\x60\0\0\0\0\0\0\0\x01\0\0\0\
\x0d\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\x11\0\0\0\0\0\0\0\x03\0\0\0\
\x05\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x1f\0\0\0\0\0\0\0\x03\0\0\0\
\x07\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x3c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x44\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x48\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x4c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x50\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x54\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x58\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x5c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x6c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x70\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x74\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x78\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x7c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x80\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x84\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x88\0\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x0e\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\
\x0c\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x0d\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\xc8\x01\0\0\0\0\0\0\x04\0\0\0\x0c\0\0\0\xd4\x01\0\0\0\0\0\0\x04\0\0\
\0\x0d\0\0\0\xec\x01\0\0\0\0\0\0\x04\0\0\0\x0e\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\
\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\
\x0a\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x36\0\0\0\0\0\0\0\x03\0\0\0\
\x0a\0\0\0\x4b\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\
\x0a\0\0\0\x75\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x8f\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\x0b\x0c\x0d\x0e\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\
\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\
\x2e\x72\x65\x6c\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\x74\0\x2e\x64\x65\x62\x75\
\x67\x5f\x6c\x6f\x63\x6c\x69\x73\x74\x73\0\x65\x76\x65\x6e\x74\x73\0\x2e\x72\
\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\
\x73\0\x6f\x6e\x5f\x63\x61\x63\x68\x65\x5f\x6d\x69\x73\x73\0\x2e\x6d\x61\x70\
\x73\0\x73\x74\x61\x63\x6b\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\x2e\
\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\
\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\
\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\
\0\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\
\x6c\x69\x6e\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\
\x65\0\x6f\x6e\x5f\x6c\x6c\x63\x5f\x6d\x69\x73\x73\x2e\x62\x70\x66\x2e\x63\0\
\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\
\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfe\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xb4\x11\0\0\0\0\0\0\x1f\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x26\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xa0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x09\0\
\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x0d\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\
\x1a\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x6d\0\0\0\x01\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\x38\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc3\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x31\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x1c\x01\0\0\0\0\0\0\x2e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4a\x01\0\0\0\
\0\0\0\x0c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xa9\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x56\x02\0\0\0\0\0\0\xd4\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa5\0\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\x0d\0\0\0\0\0\0\x50\0\0\0\0\0\
\0\0\x1a\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x4c\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2a\x04\0\0\0\0\0\0\x8c\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\0\0\0\x09\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x20\x0e\0\0\0\0\0\0\x10\x02\0\0\0\0\0\0\x1a\0\0\0\x0b\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x7a\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xb6\x04\0\0\0\0\0\0\xc9\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\x99\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x7f\x06\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x95\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x10\0\0\
\0\0\0\0\x40\0\0\0\0\0\0\0\x1a\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x12\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x06\0\0\0\0\0\0\
\x94\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0e\x01\
\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x10\0\0\0\0\0\0\x30\0\0\0\
\0\0\0\0\x1a\0\0\0\x10\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3c\x0a\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xa0\x10\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x1a\0\0\0\x12\0\
\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xdf\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xe0\x0a\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xdb\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x10\x11\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1a\0\0\0\x14\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\xcf\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x0b\
\0\0\0\0\0\0\xbd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xcb\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x11\0\0\0\0\0\0\
\x80\0\0\0\0\0\0\0\x1a\0\0\0\x16\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x85\
\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc5\x0b\0\0\0\0\0\0\x7c\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xb5\0\0\0\x03\
\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x11\0\0\0\0\0\0\x04\0\0\0\0\
\0\0\0\x1a\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x06\x01\0\0\x02\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x0c\0\0\0\0\0\0\x68\x01\0\0\0\0\0\0\x01\
\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct on_llc_miss_bpf *on_llc_miss_bpf::open(const struct bpf_object_open_opts *opts) { return on_llc_miss_bpf__open_opts(opts); }
struct on_llc_miss_bpf *on_llc_miss_bpf::open_and_load() { return on_llc_miss_bpf__open_and_load(); }
int on_llc_miss_bpf::load(struct on_llc_miss_bpf *skel) { return on_llc_miss_bpf__load(skel); }
int on_llc_miss_bpf::attach(struct on_llc_miss_bpf *skel) { return on_llc_miss_bpf__attach(skel); }
void on_llc_miss_bpf::detach(struct on_llc_miss_bpf *skel) { on_llc_miss_bpf__detach(skel); }
void on_llc_miss_bpf::destroy(struct on_llc_miss_bpf *skel) { on_llc_miss_bpf__destroy(skel); }
const void *on_llc_miss_bpf::elf_bytes(size_t *sz) { return on_llc_miss_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
on_llc_miss_bpf__assert(struct on_llc_miss_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __ON_LLC_MISS_BPF_SKEL_H__ */
