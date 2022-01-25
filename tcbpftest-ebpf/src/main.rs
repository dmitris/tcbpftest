#![no_std]
#![no_main]

use aya_bpf::{
    BpfContext,
    macros::{map, classifier},
    maps::PerfEventArray,
    programs::SkBuffContext,
};
use aya_bpf::bindings::__sk_buff;

use core::convert::TryInto;
use core::mem;
use memoffset::offset_of;

use tcbpftest_common::PacketLog;

mod bindings;
use bindings::{ethhdr, iphdr};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[classifier(name="tcbpftest")]
pub fn tcbpftest(ctx: SkBuffContext) -> i32 {
    match unsafe { try_tcbpftest(ctx) } {
        Ok(ret) => ret,
        Err(_) => 123,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &SkBuffContext, offset: usize) -> Result<*const T, ()> {
   let raw_skb  = ctx.as_ptr() as *const __sk_buff;
   let start = (*raw_skb).data as usize;
   let end = (*raw_skb).data_end as usize;
   let len = mem::size_of::<T>();

   if start + offset  + len  > end {
       return Err(());
   }

   Ok((start + offset) as *const T)
}

unsafe fn try_tcbpftest(ctx: SkBuffContext) -> Result<i32, i64> {
    let skb  = ctx.as_ptr() as *const __sk_buff;
    let offset : usize = 8;
    let val = match ptr_at::<u16>(&ctx, offset) {
	    Err(_) => return Err(123),
	    Ok(v) => v,
    };
    let proto_bytes = u16::from_be(*val);
    let log_entry = PacketLog {
        len: u32::from_be((*skb).len),
        proto: proto_bytes as u32,
    };

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(0)
}
