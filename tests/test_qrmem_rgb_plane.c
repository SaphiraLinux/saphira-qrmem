#include "qrmem.h"

#include <stdio.h>
#include <string.h>

#define NAME "/qrmem-test-rgb-plane"

static int fail;
static void ok(int yes, const char *what) {
    printf("%s %s\n", yes ? "ok" : "not ok", what);
    if (!yes) fail = 1;
}

int main(void) {
    qrmem_ap_t ap;
    qrmem_uuid_t id;
    qrmem_rec_t record;
    qrmem_id_t owner = {0,0,0};
    char err[256] = "";
    uint32_t slot, gen, qr = 0, green = 0, blue = 0;
    qrmem_aperture_unlink(NAME);
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, err); return 1;
    }
    ok(1, "create RGB fabric");
    ok(ap.bytes == 101179392u, "three-plane ABI uses 96.49 MiB aperture");
    ok(qrmem_agent_claim(&ap, "rgb-test", &slot, &gen, err, sizeof err) == 0, "claim agent");
    owner.slot=slot; owner.agent_gen=gen;
    ok(qrmem_screen_claim(&ap,0,owner,"rgb",err,sizeof err)==0,"claim screen");
    ok(qrmem_uuid_mint(&id,err,sizeof err)==0,"mint record id");
    qrmem_rec_init(&record,QRMEM_CT_WORD,id);
    qrmem_rec_add_text(&record,"scannable visual memory",23);
    ok(qrmem_tile_write(&ap,0,0,0,owner,&record,err,sizeof err)==0,"write first tile");
    for (uint32_t y=0;y<512;y++) for(uint32_t x=0;x<qrmem_viewport_x1(0);x++) {
        qr += qrmem_bitplane_get(&ap,QRMEM_PLANE_QR,0,x,y);
        green += qrmem_bitplane_get(&ap,QRMEM_PLANE_OCCUPANCY,0,x,y);
        blue += qrmem_bitplane_get(&ap,QRMEM_PLANE_CHANGE,0,x,y);
    }
    ok(qr > 0, "red QR channel contains QR modules");
    ok(green == qrmem_viewport_x1(0)*512u, "green channel fills occupied viewport");
    ok(blue == qrmem_viewport_x1(0)*512u, "blue channel marks post-baseline write");
    ok(qrmem_plane_export_tile_pbm(&ap,0,0,0,"/tmp/qrmem-rgb-tile.pbm",err,sizeof err)==0,
       "export red QR channel alone as lossless PBM");
    ok(qrmem_plane_set_baseline(&ap,0)==0,"declare baseline");
    blue=0; for(uint32_t y=0;y<512;y++) for(uint32_t x=0;x<qrmem_viewport_x1(0);x++) blue += qrmem_bitplane_get(&ap,QRMEM_PLANE_CHANGE,0,x,y);
    ok(blue==0,"baseline clears blue channel without changing QR or occupancy");
    ok(qrmem_tile_write(&ap,0,0,0,owner,&record,err,sizeof err)==0,
       "rewrite after baseline");
    blue=0; for(uint32_t y=0;y<512;y++) for(uint32_t x=0;x<qrmem_viewport_x1(0);x++) blue += qrmem_bitplane_get(&ap,QRMEM_PLANE_CHANGE,0,x,y);
    ok(blue==qrmem_viewport_x1(0)*512u,"post-baseline rewrite marks exactly its blue viewport");
    qrmem_aperture_detach(&ap); qrmem_aperture_unlink(NAME);
    return fail;
}
