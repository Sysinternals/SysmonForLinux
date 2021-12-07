# Perf Ring Buffer

## Introduction

There are two ring buffers provided by eBPF that can be used to transmit 
information from eBPF programs to the userland controller. The first is the 
perf ring buffer, and this is the default one in Sysmon, which has been around 
since at least kernel v4.15. The second one is the BPF ring buffer which was 
introduced later. This document only considers the perf ring buffer.

## Architecture

Each perf ring buffer is separate from others. In essence, the fact that they 
are separate, and that multiple tracing programs can co-exist without 
interfering with each other, is the main reason why eBPF tracers are far better 
than kaudit-based tracers (such as auditd/audispd).

The perf ring buffer is shared between the userland code and the eBPF programs:

```
struct bpf_map_def SEC("maps") eventMap = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(uint32_t),
	.max_entries = MAX_PROC, // MAX_PROC CPUs
};
```

The eventMap identifies the perf array shared between userland and eBPF. This 
map has the specific type of BPF\_MAP\_TYPE\_PERF\_EVENT\_ARRAY, a key type of 
int, and a value type of uint32\_t. The key is the index into the ring buffer, 
and the value is the size of the inserted data (data known as samples).

The userland controller sets it up:

```
    struct perf_buffer_opts         pbOpts = {};
    struct perf_buffer              *pb = NULL;

    eventMapFd = bpf_object__find_map_fd_by_name(bpfObj, "eventMap");
    if (eventMapFd <= 0) {
        fprintf(stderr, "ERROR: failed to load eventMapFd: '%s'\n", strerror(errno));
        return E_EBPF_NOMAP;
    }

    pbOpts.sample_cb = eventCb;
    pbOpts.lost_cb = eventsLostCb;
    pbOpts.ctx = context;
    pb = perf_buffer__new(eventMapFd, MAP_PAGE_COUNT, &pbOpts);
        // param 2 is page_cnt == number of pages to mmap.
    ret = libbpf_get_error(pb);
    if (ret) {
        fprintf(stderr, "ERROR: failed to setup perf_buffer: %d\n", ret);
        return E_EBPF_NORB;
    }
```

This code specifies callbacks for when we receive samples and when samples are 
dropped due to saturation. The context (ctx) is a user-specified pointer that 
will be provided to the callbacks with the data. The code also specifies the 
number of pages (4KB each on Linux) to allocate to the ring buffer.

The callback prototypes are:

```
typedef void (EventCallback_u32)(void *ctx, int cpu, void *data, __u32 size);
typedef void (EventLostCallback_u64)(void *ctx, int cpu, __u64 lostCnt);
```

From within eBPF programs, data can be sent to the perf ring buffer with:

```
ret = bpf_perf_event_output(ctx, map, flags, data, size);
```

The ctx parameter is the pointer to the parameters struct provided to the eBPF 
program. The map is that defined in the shared section, eventMap in this case. 
The flags specify which ring buffer index to write to, but is usually set to 
the define BPF\_F\_CURRENT\_CPU. The data and size specify the data.

In userland, the ring buffer is polled:

```
while (running) {
    ret = perf_buffer__poll(pb, 1000);
    // handle ret
}
```

The second parameter specifies the timeout in milliseconds. A return value of 0 
indicates a timeout occurred. A negative return value indicates a failure, 
which is most likely that the polling was interrupted by a signal. A positive 
value indicates the number of samples that were processed. Each one is fired 
individually into the sample\_cb callback.

## Issues

While the API takes a uin32\_t for the sample size parameter, the actual 
maximum size for a sample is <64KB. The actual maximum size is about (64KB - 
48) but this is configuration specific so could be smaller than this. Any 
samples sent over the maximum size will have their size parameter masked with 
0xFFFF as it is converted to a uint16\_t inside the perf subsystem. This means 
two things: first, the size parameter received in userland is wrong; and 
second, the next sample will overlap the current sample as it will be 
positioned based on the incorrect size.

As such, ensure all samples are smaller than a reasonable threshold, such as 
64000 bytes, to ensure compatibility on systems you don't control.

Another issue is saturation. Be careful to both size the ring buffer correctly, 
and also to limit the number of samples sent so that saturation is unlikely, if 
not practically impossible. Do not send fixed size buffers for non-fixed size 
fields!

If saturation is unavoidable, consider breaking samples into smaller chunks 
circa 4KB in size. These are more efficient and more will be received in 
userland. You might consider that receiving 7 out of 8 4KB chunks of a sample 
has some value, even though a chunk is missing. Use counters, etc, to 
reconstruct in userland and identify lost chunks.
