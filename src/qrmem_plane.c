/* QRMem visual stack.  Plane 0 is the only phone-scannable plane.  Planes 1
 * and 2 are aligned state masks for people and visual models; they are never
 * blended into the QR export. */
#include "qrmem.h"

#include <qrencode.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void plane_err(char *err, size_t n, const char *fmt, ...) {
    va_list ap;
    if (!err || !n) return;
    va_start(ap, fmt); vsnprintf(err, n, fmt, ap); va_end(ap);
}

static const char *type_name(uint16_t type) {
    switch (type) {
    case QRMEM_CT_WORD: return "word";
    case QRMEM_CT_IDEA: return "idea";
    case QRMEM_CT_FACT: return "fact";
    case QRMEM_CT_PTR: return "ptr";
    default: return "unknown";
    }
}

/* JSON escaping is deliberately small and strict.  qrmem text is UTF-8 at the
 * boundary; controls are escaped so each QR is a self-contained UTF-8 record,
 * not a padded cell image or an ambiguous line protocol. */
static int json_quote(char *out, size_t cap, const char *s, size_t n) {
    size_t o = 0;
    if (cap < 3) return -1;
    out[o++] = '"';
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { if (o + 2 >= cap) return -1; out[o++]='\\'; out[o++]=(char)c; }
        else if (c < 0x20u) { if (o + 6 >= cap) return -1; o += (size_t)snprintf(out+o, cap-o, "\\u%04x", c); }
        else { if (o + 1 >= cap) return -1; out[o++]=(char)c; }
    }
    if (o + 2 > cap) return -1;
    out[o++] = '"'; out[o] = '\0'; return (int)o;
}

static int record_json(const qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                       uint32_t slot, const qrmem_rec_t *r, char *out,
                       size_t cap) {
    char fid[QRMEM_UUID_TEXT_LEN + 1], rid[QRMEM_UUID_TEXT_LEN + 1];
    char project[QRMEM_PROJECT_MAX * 6u + 3u], text[QRMEM_CELL_BODY * 6u + 3u];
    char index[QRMEM_CELL_BODY * 6u + 3u], body_hex[QRMEM_CELL_BODY * 2u + 1u];
    char links[QRMEM_CELL_LINKS * (QRMEM_UUID_TEXT_LEN + 3u) + 3u];
    const char *body = "", *key = ""; size_t body_n = 0, key_n = 0, plen, lo = 0;
    int n;
    qrmem_uuid_text(&ap->hdr->fabric_id, fid, sizeof fid);
    qrmem_uuid_text(&r->id, rid, sizeof rid);
    plen = atomic_load_explicit(&ap->screens[screen].project_len, memory_order_acquire);
    if (plen > QRMEM_PROJECT_MAX) plen = 0;
    if (qrmem_rec_get_text(r, &body, &body_n) != 0) { body = ""; body_n = 0; }
    if (qrmem_rec_get_text_tag(r, QRMEM_TLV_INDEX_KEY, &key, &key_n) != 0) { key = ""; key_n = 0; }
    if (json_quote(project, sizeof project, ap->screens[screen].project, plen) < 0 ||
        json_quote(text, sizeof text, body, body_n) < 0 ||
        json_quote(index, sizeof index, key, key_n) < 0) return -1;
    for (uint16_t i=0; i<r->body_len; i++)
        snprintf(body_hex + i*2u, sizeof body_hex - i*2u, "%02x", r->body[i]);
    body_hex[r->body_len * 2u] = '\0';
    links[lo++]='[';
    for (uint16_t i=0; i<r->n_links; i++) {
        char link[QRMEM_UUID_TEXT_LEN + 1];
        if (i) links[lo++]=',';
        qrmem_uuid_text(&r->links[i],link,sizeof link);
        links[lo++]='"'; memcpy(links+lo,link,QRMEM_UUID_TEXT_LEN); lo+=QRMEM_UUID_TEXT_LEN; links[lo++]='"';
    }
    links[lo++]=']'; links[lo]='\0';
    n = snprintf(out, cap,
        "{\"v\":1,\"fabric\":\"%s\",\"project\":%s,\"project_identity\":\"%s/%u\",\"screen\":%u,\"block\":%u,\"slot\":%u,\"id\":\"%s\",\"type\":\"%s\",\"generation\":%u,\"written_ns\":%llu,\"index\":%s,\"text\":%s,\"body_hex\":\"%s\",\"links\":%s,\"witness32\":\"%08x\"}",
        fid, project, fid, screen, screen, block, slot, rid, type_name(r->type),
        (unsigned)r->generation, (unsigned long long)qrmem_rec_written_ns(r), index, text,
        body_hex, links, (unsigned)qrmem_rec_witness(r));
    return n >= 0 && (size_t)n < cap ? n : -1;
}

static void fill_viewport(qrmem_ap_t *ap, uint32_t plane, uint32_t screen,
                          uint32_t block, uint32_t slot, int value) {
    uint32_t row = qrmem_record_row(block, slot), col = qrmem_record_col(block, slot);
    for (uint32_t y = qrmem_viewport_y0(row); y < qrmem_viewport_y1(row); y++)
        for (uint32_t x = qrmem_viewport_x0(col); x < qrmem_viewport_x1(col); x++)
            qrmem_bitplane_set(ap, plane, screen, x, y, value);
}

static int render_record(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                         uint32_t slot) {
    qrmem_rec_t r; char payload[2048]; QRcode *code;
    uint32_t row, col, x0, x1, y0, y1, total, scale, ox, oy;
    /* White QR background, including the four-module quiet zone. */
    fill_viewport(ap, QRMEM_PLANE_QR, screen, block, slot, 0);
    if (qrmem_cell_read(ap, screen, block, slot, &r, NULL, 0) != 0) {
        fill_viewport(ap, QRMEM_PLANE_OCCUPANCY, screen, block, slot, 0);
        return 0;
    }
    fill_viewport(ap, QRMEM_PLANE_OCCUPANCY, screen, block, slot, 1);
    if (record_json(ap, screen, block, slot, &r, payload, sizeof payload) < 0)
        return -1;
    code = QRcode_encodeString8bit(payload, 0, QR_ECLEVEL_M);
    if (!code) return -1;
    row=qrmem_record_row(block,slot); col=qrmem_record_col(block,slot);
    x0=qrmem_viewport_x0(col); x1=qrmem_viewport_x1(col);
    y0=qrmem_viewport_y0(row); y1=qrmem_viewport_y1(row);
    total=(uint32_t)code->width + 8u;
    scale=(x1-x0)/(total); if ((y1-y0)/total < scale) scale=(y1-y0)/total;
    if (!scale) { QRcode_free(code); return -1; }
    ox=x0+((x1-x0)-total*scale)/2u+4u*scale;
    oy=y0+((y1-y0)-total*scale)/2u+4u*scale;
    for (int my=0; my<code->width; my++) for (int mx=0; mx<code->width; mx++)
        if (code->data[(size_t)my*code->width+mx] & 1u)
            for (uint32_t sy=0; sy<scale; sy++) for (uint32_t sx=0; sx<scale; sx++)
                qrmem_bitplane_set(ap,QRMEM_PLANE_QR,screen,ox+(uint32_t)mx*scale+sx,oy+(uint32_t)my*scale+sy,1);
    QRcode_free(code);
    return 0;
}

int qrmem_plane_encode_block(const qrmem_ap_t *ap, uint32_t screen,
                             uint32_t block, unsigned char *out) {
    (void)ap; (void)screen; (void)block; (void)out;
    /* The ABI no longer has a visual block symbol: each slot is one QR Code. */
    return -1;
}

int qrmem_plane_store_block(qrmem_ap_t *ap, uint32_t screen, uint32_t block) {
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen) || !qrmem_block_valid(block)) return -1;
    for (uint32_t slot=0; slot<QRMEM_SLOTS_PER_BLOCK; slot++) {
        if (render_record(ap,screen,block,slot) != 0) return -1;
    }
    return 0;
}

int qrmem_plane_init(qrmem_ap_t *ap) {
    if (!ap || !ap->plane) return -1;
    memset((void *)ap->plane, 0, (size_t)QRMEM_SCREENS * QRMEM_PLANES_SCREEN_BYTES);
    return 0;
}

int qrmem_plane_set_baseline(qrmem_ap_t *ap, uint32_t screen) {
    uint64_t generation;
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen)) return -1;
    generation = atomic_load_explicit(&ap->screens[screen].generation, memory_order_acquire);
    atomic_store_explicit(&ap->screens[screen].baseline_generation, generation,
                          memory_order_release);
    for (uint32_t block=0; block<QRMEM_BLOCKS_PER_SCREEN; block++)
        for (uint32_t slot=0; slot<QRMEM_SLOTS_PER_BLOCK; slot++)
            fill_viewport(ap,QRMEM_PLANE_CHANGE,screen,block,slot,0);
    return 0;
}

void qrmem_plane_mark_changed(qrmem_ap_t *ap, uint32_t screen,
                              uint32_t block, uint32_t slot) {
    uint64_t now, baseline;
    if (!ap || !qrmem_screen_valid(screen) || !qrmem_block_valid(block) ||
        !qrmem_slot_valid(slot)) return;
    now = atomic_load_explicit(&ap->screens[screen].generation, memory_order_acquire);
    baseline = atomic_load_explicit(&ap->screens[screen].baseline_generation,
                                    memory_order_acquire);
    if (now > baseline)
        fill_viewport(ap,QRMEM_PLANE_CHANGE,screen,block,slot,1);
}

int qrmem_plane_export_tile_pbm(const qrmem_ap_t *ap, uint32_t screen,
                                uint32_t block, uint32_t slot, const char *path,
                                char *err, size_t errlen) {
    FILE *f;
    uint32_t row, col, x0, x1, y0, y1, w, h;
    if (!ap || !path || !qrmem_screen_valid(screen) || !qrmem_block_valid(block) ||
        !qrmem_slot_valid(slot)) { plane_err(err,errlen,"invalid QR tile export"); return -1; }
    row=qrmem_record_row(block,slot); col=qrmem_record_col(block,slot);
    x0=qrmem_viewport_x0(col); x1=qrmem_viewport_x1(col);
    y0=qrmem_viewport_y0(row); y1=qrmem_viewport_y1(row); w=x1-x0; h=y1-y0;
    f=fopen(path,"wb"); if (!f) { plane_err(err,errlen,"cannot open PBM export"); return -1; }
    if (fprintf(f,"P4\n%u %u\n",w,h)<0) { fclose(f); return -1; }
    for(uint32_t y=y0;y<y1;y++) for(uint32_t xb=0;xb<(w+7u)/8u;xb++) {
        unsigned char octet=0;
        for(uint32_t b=0;b<8u;b++) { uint32_t x=xb*8u+b; if(x<w && qrmem_plane_get(ap,screen,x0+x,y)) octet|=(unsigned char)(1u<<(7u-b)); }
        if(fputc(octet,f)==EOF) { fclose(f); plane_err(err,errlen,"cannot write PBM export"); return -1; }
    }
    if(fclose(f)!=0) { plane_err(err,errlen,"cannot close PBM export"); return -1; }
    return 0;
}

int qrmem_plane_verify_block(const qrmem_ap_t *ap, uint32_t screen,
                             uint32_t block, char *err, size_t errlen) {
    /* A visual check must not silently regenerate a plane.  The image-recovery
     * verifier is the authority for QR decoding; this API only assures callers
     * that the addressed block exists in this ABI. */
    if (!ap || !ap->plane || !qrmem_screen_valid(screen) || !qrmem_block_valid(block)) {
        plane_err(err,errlen,"record group is outside the fabric"); return 1;
    }
    return 0;
}

int qrmem_plane_render(const qrmem_ap_t *ap, uint32_t screen, uint32_t x0,
                       uint32_t y0, uint32_t w, uint32_t h, char *out,
                       size_t cap, size_t *n_out, char *err, size_t errlen) {
    size_t need=(size_t)h*((size_t)w+1u);
    if (!ap || !out || !n_out || w==0 || h==0 || x0+w>QRMEM_PLANE_DIM || y0+h>QRMEM_PLANE_DIM || need+1u>cap) {
        plane_err(err,errlen,"invalid QR-plane render window"); return -1;
    }
    for(uint32_t y=0;y<h;y++) { for(uint32_t x=0;x<w;x++) out[(size_t)y*(w+1u)+x]=qrmem_plane_get(ap,screen,x0+x,y0+y)?'#':'.'; out[(size_t)y*(w+1u)+w]='\n'; }
    out[need]='\0'; *n_out=need; return 0;
}
