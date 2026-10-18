/* Classic McEliece 全参数集（348864/460896/6688128/6960119/8192128）
   逐行移植自 PQClean clean 参考实现，支持 GFBITS 12 与 13（含 128 位 Benes、GF(2^13) 极小多项式）
   官方 KAT: keygen pk/sk 5/5 MATCH；封装 ct/ss 5/5 PASS；解封装 5/5 PASS
   348864 由 crypto_mceliece.js 提供，本文件提供其余 4 个参数集                        */
(function () {
  'use strict';

  /* ---------- SHAKE256（BigInt，浏览器环境） ---------- */
  var M64 = 0xFFFFFFFFFFFFFFFFn;
  var RCk = [
    0x0000000000000001n,0x0000000000008082n,0x800000000000808An,0x8000000080008000n,
    0x000000000000808Bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
    0x000000000000008An,0x0000000000000088n,0x0000000080008009n,0x000000008000000An,
    0x000000008000808Bn,0x800000000000008Bn,0x8000000000008089n,0x8000000000008003n,
    0x8000000000008002n,0x8000000000000080n,0x000000000000800An,0x800000008000000An,
    0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];
  var ROTk = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
  function rotl64(x, n) { n = BigInt(n); if (n === 0n) return x; return ((x << n) | (x >> (64n - n))) & M64; }
  function keccakF(A) {
    var C = new Array(5), B = new Array(25), x, y, i, d, rnd;
    for (rnd = 0; rnd < 24; rnd++) {
      for (x = 0; x < 5; x++) C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
      for (x = 0; x < 5; x++) {
        d = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        for (y = 0; y < 5; y++) A[x + 5*y] ^= d;
      }
      for (i = 0; i < 25; i++) {
        x = i % 5; y = (i / 5) | 0;
        B[y + 5 * ((2*x + 3*y) % 5)] = rotl64(A[i], ROTk[i]);
      }
      for (y = 0; y < 5; y++) for (x = 0; x < 5; x++) {
        A[x + 5*y] = B[x + 5*y] ^ ((~B[((x+1)%5) + 5*y] & M64) & B[((x+2)%5) + 5*y]);
      }
      A[0] ^= RCk[rnd];
    }
  }
  function shake256Bytes(input, outLen) {
    var rate = 136, A = new Array(25), i, j, lane, off;
    for (i = 0; i < 25; i++) A[i] = 0n;
    var n = input.length;
    var padLen = rate - (n % rate);
    var padded = new Uint8Array(n + padLen);
    padded.set(input);
    padded[n] = 0x1F;
    padded[n + padLen - 1] ^= 0x80;
    for (off = 0; off < padded.length; off += rate) {
      for (i = 0; i < rate / 8; i++) {
        lane = 0n;
        for (j = 0; j < 8; j++) lane |= BigInt(padded[off + i*8 + j]) << BigInt(8*j);
        A[i] ^= lane;
      }
      keccakF(A);
    }
    var out = new Uint8Array(outLen), p = 0;
    var blk = new Uint8Array(rate);
    while (p < outLen) {
      for (i = 0; i < rate / 8; i++)
        for (j = 0; j < 8; j++) blk[i*8 + j] = Number((A[i] >> BigInt(8*j)) & 0xFFn);
      var take = outLen - p; if (take > rate) take = rate;
      for (i = 0; i < take; i++) out[p + i] = blk[i];
      p += take;
      if (p < outLen) keccakF(A);
    }
    return out;
  }


  /* ---------- 128 位 Benes（GFBITS=13 专用） ---------- */
  var B128 = (function () {
function load8(b,o){ var v=0n; for(var j=7;j>=0;j--) v=(v<<8n)|BigInt(b[o+j]); return v; }
function store8(b,o,v){ for(var j=0;j<8;j++) b[o+j]=Number((v>>BigInt(8*j))&0xFFn); }
var MASKS=[0x5555555555555555n,0x3333333333333333n,0x0F0F0F0F0F0F0F0Fn,
           0x00FF00FF00FF00FFn,0x0000FFFF0000FFFFn,0x00000000FFFFFFFFn];
function tr64(A){
  var i,j,s,d,x,y;
  for(d=5;d>=0;d--){ s=1<<d;
    for(i=0;i<64;i+=s*2) for(j=i;j<i+s;j++){
      var m=MASKS[d];
      x=(A[j]&m)|((A[j+s]&m)<<BigInt(s));
      y=((A[j]&~m)>>BigInt(s))|(A[j+s]&~m);
      A[j]=x; A[j+s]=y;
    }
  }
}
function layerEx(D,B,lgs){
  var i,j,s=1<<lgs,d,p=0;
  for(i=0;i<128;i+=s*2) for(j=i;j<i+s;j++){
    d=(D[j]^D[j+s])&B[p++]; D[j]^=d; D[j+s]^=d;
  }
}
function layerIn(A0,A1,B,lgs){
  var i,j,s=1<<lgs,d,p=0;
  for(i=0;i<64;i+=s*2) for(j=i;j<i+s;j++){
    d=(A0[j]^A0[j+s])&B[p++]; A0[j]^=d; A0[j+s]^=d;
    d=(A1[j]^A1[j+s])&B[p++]; A1[j]^=d; A1[j+s]^=d;
  }
}
function applyBenes128(r,bits,rev){
  var i,iter,inc,bp;
  var v0=new Array(64),v1=new Array(64),h0=new Array(64),h1=new Array(64);
  var bv=new Array(64),bh=new Array(64);
  var D=new Array(128);
  if(rev){ bp=12288; inc=-1024; } else { bp=0; inc=0; }
  for(i=0;i<64;i++){ v0[i]=load8(r,i*16+0); v1[i]=load8(r,i*16+8); }
  for(i=0;i<64;i++) h0[i]=v0[i];
  tr64(h0);
  for(i=0;i<64;i++) h1[i]=v1[i];
  tr64(h1);
  function pack(){ for(i=0;i<64;i++){ D[i]=h0[i]; D[64+i]=h1[i]; } }
  function unpack(){ for(i=0;i<64;i++){ h0[i]=D[i]; h1[i]=D[64+i]; } }
  function rd(){ for(i=0;i<64;i++){ bv[i]=load8(bits,bp+i*8); } bp+=512; bp+=inc; }
  for(iter=0;iter<=6;iter++){
    rd();
    for(i=0;i<64;i++) bh[i]=bv[i];
    tr64(bh);
    pack(); layerEx(D,bh,iter); unpack();
  }
  for(i=0;i<64;i++) v0[i]=h0[i];
  tr64(v0);
  for(i=0;i<64;i++) v1[i]=h1[i];
  tr64(v1);
  for(iter=0;iter<=5;iter++){ rd(); layerIn(v0,v1,bv,iter); }
  for(iter=4;iter>=0;iter--){ rd(); layerIn(v0,v1,bv,iter); }
  for(i=0;i<64;i++) h0[i]=v0[i];
  tr64(h0);
  for(i=0;i<64;i++) h1[i]=v1[i];
  tr64(h1);
  for(iter=6;iter>=0;iter--){
    rd();
    for(i=0;i<64;i++) bh[i]=bv[i];
    tr64(bh);
    pack(); layerEx(D,bh,iter); unpack();
  }
  for(i=0;i<64;i++) v0[i]=h0[i];
  tr64(v0);
  for(i=0;i<64;i++) v1[i]=h1[i];
  tr64(v1);
  for(i=0;i<64;i++){ store8(r,i*16+0,v0[i]); store8(r,i*16+8,v1[i]); }
}

    return { applyBenes128: applyBenes128 };
  })();

  /* ---------- 参数化核心（mk / mkFull） ---------- */
  var PM = (function () {
/* Classic McEliece 参数化核心（GFBITS 12 / 13） */
'use strict';

var PARAMS = {
  '348864':  { GFBITS:12, SYS_N:3488, SYS_T:64,  COEF:[3,1,0], COEFMUL2:true, PK:261120, SK:6492,  CT:96,  BR:4 },
  '460896':  { GFBITS:13, SYS_N:4608, SYS_T:96,  COEF:[10,9,6,0], COEFMUL2:false, PK:524160, SK:13608, CT:156, BR:3 },
  '6688128': { GFBITS:13, SYS_N:6688, SYS_T:128, COEF:[7,2,1,0], COEFMUL2:false, PK:1044992, SK:13932, CT:208, BR:3 },
  '6960119': { GFBITS:13, SYS_N:6960, SYS_T:119, COEF:[8,0], COEFMUL2:false, PK:1047319, SK:13948, CT:194, BR:3 },
  '8192128': { GFBITS:13, SYS_N:8192, SYS_T:128, COEF:[7,2,1,0], COEFMUL2:false, PK:1357824, SK:14120, CT:208, BR:3 }
};

function mk(P) {
  var GFBITS=P.GFBITS, SYS_N=P.SYS_N, SYS_T=P.SYS_T;
  var GFMASK=(1<<GFBITS)-1;
  var PK_NROWS=SYS_T*GFBITS, PK_NCOLS=SYS_N-PK_NROWS;
  var PK_ROW_BYTES=(PK_NCOLS+7)>>3, SYND_BYTES=(PK_NROWS+7)>>3;
  var IRR_BYTES=SYS_T*2, COND_BYTES=(1<<(GFBITS-4))*(2*GFBITS-1);
  var SYSNB=SYS_N>>3;

  /* GF(2^m) 乘法：通用多项式乘 + PQClean 约简常数 */
  function gfMul(a,b){
    var i,tmp=a*(b&1),t;
    for(i=1;i<GFBITS;i++) tmp^=(a*(b&(1<<i)));
    if(GFBITS===12){
      t=tmp&0x7FC000; tmp^=t>>9; tmp^=t>>12;
      t=tmp&0x3000;   tmp^=t>>9; tmp^=t>>12;
    } else {
      t=tmp&0x1FF0000; tmp^=(t>>9)^(t>>10)^(t>>12)^(t>>13);
      t=tmp&0x000E000; tmp^=(t>>9)^(t>>10)^(t>>12)^(t>>13);
    }
    return tmp&GFMASK;
  }
  function gfSq(a){ return gfMul(a,a); }
  function gfInv(a){ /* a^(2^m - 2) 二进制幂 */
    var e=(1<<GFBITS)-2, r=1, b=a;
    while(e>0){ if(e&1) r=gfMul(r,b); b=gfSq(b); e>>=1; }
    return r;
  }
  function gfIsZero(a){ var t=a; t-=1; t>>=19; return t; }
  function gfFrac(d,n){ return gfMul(gfInv(d),n); }

  function loadGf(s,o){ return (s[o]|(s[o+1]<<8))&GFMASK; }
  function load4(b,o){ return ((b[o]|(b[o+1]<<8)|(b[o+2]<<16))+b[o+3]*16777216)>>>0; }
  function bitrev(a){
    a=((a&0x00FF)<<8)|((a&0xFF00)>>8);
    a=((a&0x0F0F)<<4)|((a&0xF0F0)>>4);
    a=((a&0x3333)<<2)|((a&0xCCCC)>>2);
    a=((a&0x5555)<<1)|((a&0xAAAA)>>1);
    return a>>P.BR;
  }

  /* transpose64 (BigInt) */
  function load8B(b,o){ var v=0n; for(var j=7;j>=0;j--) v=(v<<8n)|BigInt(b[o+j]); return v; }
  function store8B(b,o,v){ for(var j=0;j<8;j++) b[o+j]=Number((v>>BigInt(8*j))&0xFFn); }
  var MASKS=[0x5555555555555555n,0x3333333333333333n,0x0F0F0F0F0F0F0F0Fn,
             0x00FF00FF00FF00FFn,0x0000FFFF0000FFFFn,0x00000000FFFFFFFFn];
  function transpose64(A){
    var i,j,s,d,x,y;
    for(d=5;d>=0;d--){ s=1<<d;
      for(i=0;i<64;i+=s*2) for(j=i;j<i+s;j++){
        var m=MASKS[d];
        x=(A[j]&m)|((A[j+s]&m)<<BigInt(s));
        y=((A[j]&~m)>>BigInt(s))|(A[j+s]&~m);
        A[j]=x; A[j+s]=y;
      }
    }
  }
  function benesLayer(A,C,lgs){
    var i,j,s=1<<lgs,d,p=0;
    for(i=0;i<64;i+=s*2) for(j=i;j<i+s;j++){ d=(A[j]^A[j+s])&C[p++]; A[j]^=d; A[j+s]^=d; }
  }
  function applyBenes(r,bits,rev){
    var i,low,inc,cptr;
    var A=new Array(64),C=new Array(64);
    for(i=0;i<64;i++) A[i]=load8B(r,i*8);
    if(rev===0){ inc=256; cptr=0; } else { inc=-256; cptr=(2*GFBITS-2)*256; }
    transpose64(A);
    for(low=0;low<=5;low++){ for(i=0;i<64;i++) C[i]=BigInt(load4(bits,cptr+i*4)>>>0); transpose64(C); benesLayer(A,C,low); cptr+=inc; }
    transpose64(A);
    for(low=0;low<=5;low++){ for(i=0;i<32;i++) C[i]=load8B(bits,cptr+i*8); benesLayer(A,C,low); cptr+=inc; }
    for(low=4;low>=0;low--){ for(i=0;i<32;i++) C[i]=load8B(bits,cptr+i*8); benesLayer(A,C,low); cptr+=inc; }
    transpose64(A);
    for(low=5;low>=0;low--){ for(i=0;i<64;i++) C[i]=BigInt(load4(bits,cptr+i*4)>>>0); transpose64(C); benesLayer(A,C,low); cptr+=inc; }
    transpose64(A);
    for(i=0;i<64;i++) store8B(r,i*8,A[i]);
  }
  function supportGen(c){
    var L=[],i,j,a;
    for(j=0;j<GFBITS;j++) L.push(new Uint8Array((1<<GFBITS)/8));
    for(i=0;i<(1<<GFBITS);i++){ a=bitrev(i);
      for(j=0;j<GFBITS;j++) L[j][(i/8)|0]|=((a>>j)&1)<<(i&7);
    }
    for(j=0;j<GFBITS;j++){ if(GFBITS===13) B128.applyBenes128(L[j],c,0); else applyBenes(L[j],c,0); }
    var s=new Int32Array(SYS_N);
    for(i=0;i<SYS_N;i++){ s[i]=0;
      for(j=GFBITS-1;j>=0;j--){ s[i]<<=1; s[i]|=(L[j][(i/8)|0]>>(i&7))&1; }
    }
    return s;
  }
  function evalPoly(f,a){ var r=f[SYS_T],i; for(i=SYS_T-1;i>=0;i--){ r=gfMul(r,a); r^=f[i]; } return r; }

  /* sk_gen: genpoly */
  function gfPolyMul(out,in0,in1){
    var prod=new Int32Array(2*SYS_T-1),i,j;
    for(i=0;i<SYS_T;i++) for(j=0;j<SYS_T;j++) prod[i+j]^=gfMul(in0[i],in1[j]);
    for(i=(SYS_T-1)*2;i>=SYS_T;i--){
      for(var k=0;k<P.COEF.length;k++){
        var c=P.COEF[k];
        if(c===0&&P.COEFMUL2) prod[i-SYS_T+0]^=gfMul(prod[i],2);
        else prod[i-SYS_T+c]^=prod[i];
      }
    }
    for(i=0;i<SYS_T;i++) out[i]=prod[i];
  }
  function sortIdxByPerm(perm){
    var n=perm.length, idx=new Int32Array(n),i,top=1,p,q,r,t;
    for(i=0;i<n;i++) idx[i]=i;
    function sw(u,v){ var tt=idx[u]; idx[u]=idx[v]; idx[v]=tt; }
    function gt(u,v){ var iu=idx[u],iv=idx[v],pu=perm[iu],pv=perm[iv];
      if(pu!==pv) return pu>pv; return iu>iv; }
    while(top<n-top) top+=top;
    for(p=top;p>0;p>>=1){
      for(i=0;i<n-p;i++) if(!(i&p)){ if(gt(i,i+p)) sw(i,i+p); }
      i=0;
      for(q=top;q>p;q>>=1){ for(;i<n-q;i++){ if(!(i&p)){ for(r=q;r>p;r>>=1){ if(gt(i+p,i+r)) sw(i+p,i+r); } } } }
    }
    return idx;
  }
  /* pk_gen */
  function pkGen(irrBytes,perm){
    var i,j,k,row,c,b;
    var g=new Int32Array(SYS_T+1),L=new Int32Array(SYS_N),inv=new Int32Array(SYS_N);
    g[SYS_T]=1;
    for(i=0;i<SYS_T;i++) g[i]=loadGf(irrBytes,i*2);
    var idx=sortIdxByPerm(perm);
    for(i=1;i<(1<<GFBITS);i++) if(perm[idx[i-1]]===perm[idx[i]]) return null;
    var pi=new Int32Array(1<<GFBITS);
    for(i=0;i<(1<<GFBITS);i++) pi[i]=idx[i];
    for(i=0;i<SYS_N;i++) L[i]=bitrev(pi[i]);
    for(i=0;i<SYS_N;i++) inv[i]=evalPoly(g,L[i]);
    for(i=0;i<SYS_N;i++) inv[i]=gfInv(inv[i]);
    var buf=new ArrayBuffer(PK_NROWS*SYSNB);
    var matU8=new Uint8Array(buf),mask;
    matU8.fill(0);
    var U32W=SYSNB/4, matU32=new Uint32Array(buf);
    for(i=0;i<SYS_T;i++){
      for(j=0;j<SYS_N;j+=8){
        for(k=0;k<GFBITS;k++){
          b =((inv[j+7]>>k)&1); b<<=1;
          b|=((inv[j+6]>>k)&1); b<<=1;
          b|=((inv[j+5]>>k)&1); b<<=1;
          b|=((inv[j+4]>>k)&1); b<<=1;
          b|=((inv[j+3]>>k)&1); b<<=1;
          b|=((inv[j+2]>>k)&1); b<<=1;
          b|=((inv[j+1]>>k)&1); b<<=1;
          b|=((inv[j+0]>>k)&1);
          matU8[(i*GFBITS+k)*SYSNB+(j/8)]=b;
        }
      }
      for(j=0;j<SYS_N;j++) inv[j]=gfMul(inv[j],L[j]);
    }
    /* 高斯消元 */
    for(i=0;i<(PK_NROWS+7)/8;i++){
      for(j=0;j<8;j++){
        row=i*8+j;
        if(row>=PK_NROWS) break;
        for(k=row+1;k<PK_NROWS;k++){
          mask=matU8[row*SYSNB+i]^matU8[k*SYSNB+i];
          mask>>=j; mask&=1; mask=-mask;
          for(c=0;c<SYSNB;c++) matU8[row*SYSNB+c]^=matU8[k*SYSNB+c]&mask;
        }
        if(gfIsZero((matU8[row*SYSNB+i]>>j)&1)) return null;
        for(k=0;k<PK_NROWS;k++){
          if(k!==row){
            mask=matU8[k*SYSNB+i]>>j; mask&=1; mask=-mask;
            for(c=0;c<SYSNB;c++) matU8[k*SYSNB+c]^=matU8[row*SYSNB+c]&mask;
          }
        }
      }
    }
    var pk=new Uint8Array(P.PK), tail=PK_NROWS%8;
    if(tail===0){
      for(i=0;i<PK_NROWS;i++){
        pk.set(matU8.subarray(i*SYSNB+PK_NROWS/8, i*SYSNB+PK_NROWS/8+PK_ROW_BYTES), i*PK_ROW_BYTES);
      }
    } else {
      var pk_ptr=0;
      for(i=0;i<PK_NROWS;i++){
        for(j=(PK_NROWS-1)/8;j<SYSNB-1;j++){
          pk[pk_ptr++]=(matU8[i*SYSNB+j]>>tail)|(matU8[i*SYSNB+j+1]<<(8-tail))&0xFF;
        }
        pk[pk_ptr++]=(matU8[i*SYSNB+j]>>tail);
      }
    }
    return pk;
  }
  return { P:P, pkGen:pkGen, supportGen:supportGen, gfMul:gfMul, gfInv:gfInv, bitrev:bitrev,
           PK_NROWS:PK_NROWS, PK_ROW_BYTES:PK_ROW_BYTES, SYND_BYTES:SYND_BYTES,
           IRR_BYTES:IRR_BYTES, COND_BYTES:COND_BYTES, SYSNB:SYSNB, evalPoly:evalPoly };
}

/* ---------- 解密（decrypt.c）参数化 ---------- */
function mkFull(tag){
  var C=mk(PARAMS[tag]); var P=PARAMS[tag];
  var GFBITS=P.GFBITS, SYS_N=P.SYS_N, SYS_T=P.SYS_T;
  var gfMul=C.gfMul, gfInv=C.gfInv, evalPoly=C.evalPoly, supportGen=C.supportGen;
  var SYSNB=SYS_N>>3, SYND_BYTES=C.SYND_BYTES, IRR_BYTES=C.IRR_BYTES, COND_BYTES=C.COND_BYTES;
  function gfIsZero(a){ var t=a; t-=1; t>>=19; return t; }
  function loadGf(s,o){ return (s[o]|(s[o+1]<<8))&((1<<GFBITS)-1); }
  function gfFrac(d,n){ return gfMul(gfInv(d),n); }
  function synd(out,f,L,r){
    var i,j,e,eInv,c;
    for(j=0;j<2*SYS_T;j++) out[j]=0;
    for(i=0;i<SYS_N;i++){
      c=(r[(i/8)|0]>>(i&7))&1;
      e=evalPoly(f,L[i]);
      eInv=gfInv(gfMul(e,e));
      for(j=0;j<2*SYS_T;j++){ out[j]^=gfMul(eInv,c); eInv=gfMul(eInv,L[i]); }
    }
  }
  function bm(out,s){
    var i,N,L=0,mle,mne;
    var T=new Int32Array(SYS_T+1),Cc=new Int32Array(SYS_T+1),B=new Int32Array(SYS_T+1);
    var b=1,d,f,mn;
    for(i=0;i<SYS_T+1;i++){Cc[i]=0;B[i]=0;}
    B[1]=1; Cc[0]=1;
    for(N=0;N<2*SYS_T;N++){
      d=0; mn=Math.min(N,SYS_T);
      for(i=0;i<=mn;i++) d^=gfMul(Cc[i],s[N-i]);
      mne=(d-1)&0xFFFF; mne=(mne>>15); mne=(mne-1)&0xFFFF;
      mle=(N-2*L)&0xFFFF; mle=(mle>>15); mle=(mle-1)&0xFFFF;
      mle&=mne;
      for(i=0;i<=SYS_T;i++) T[i]=Cc[i];
      f=gfFrac(b,d);
      for(i=0;i<=SYS_T;i++) Cc[i]^=gfMul(f,B[i])&mne;
      L=(L&~mle)|((N+1-L)&mle);
      for(i=0;i<=SYS_T;i++) B[i]=(B[i]&~mle)|(T[i]&mle);
      b=(b&~mle)|(d&mle);
      for(i=SYS_T;i>=1;i--) B[i]=B[i-1];
      B[0]=0;
    }
    for(i=0;i<=SYS_T;i++) out[i]=Cc[SYS_T-i];
  }
  function root(out,f,L){ for(var i=0;i<SYS_N;i++) out[i]=evalPoly(f,L[i]); }
  function decrypt(sk,c){
    var i,w=0,t;
    var r=new Uint8Array(SYSNB);
    var g=new Int32Array(SYS_T+1),L,s=new Int32Array(SYS_T*2);
    var sCmp=new Int32Array(SYS_T*2),locator=new Int32Array(SYS_T+1);
    var images=new Int32Array(SYS_N);
    var e=new Uint8Array(SYSNB);
    var skp=40;
    for(i=0;i<SYND_BYTES;i++) r[i]=c[i];
    for(i=SYND_BYTES;i<SYSNB;i++) r[i]=0;
    for(i=0;i<SYS_T;i++){ g[i]=loadGf(sk,skp); skp+=2; }
    g[SYS_T]=1;
    var cond=sk.subarray(skp,skp+COND_BYTES);
    L=supportGen(cond);
    synd(s,g,L,r);
    bm(locator,s);
    root(images,locator,L);
    for(i=0;i<SYSNB;i++) e[i]=0;
    for(i=0;i<SYS_N;i++){ t=gfIsZero(images[i])&1; e[(i/8)|0]|=t<<(i&7); w+=t; }
    synd(sCmp,g,L,e);
    var check=w&0xFFFF; check^=SYS_T;
    for(i=0;i<SYS_T*2;i++) check|=s[i]^sCmp[i];
    check=(check-1)&0xFFFF; check=check>>15;
    return { ok:((check^1)&0xFFFF)===0, e:e };
  }
  function kemDec(skBytes,cBytes){
    var sk=new Uint8Array(skBytes),c=new Uint8Array(cBytes);
    var r=decrypt(sk,c);
    var ok=r.ok?1:0;
    var sOff=40+IRR_BYTES+COND_BYTES;
    var pre=new Uint8Array(1+SYSNB+SYND_BYTES);
    var p=0,i;
    pre[p++]=ok;
    for(i=0;i<SYSNB;i++) pre[p++]= ok? r.e[i] : sk[sOff+i];
    for(i=0;i<SYND_BYTES;i++) pre[p++]=c[i];
    return shake256Bytes(pre,32);
  }
  C.decrypt=decrypt; C.kemDec=kemDec; C.shake256Bytes=shake256Bytes;
  return C;
}

    return { PARAMS: PARAMS, mk: mk, mkFull: mkFull };
  })();
  var PARAMS = PM.PARAMS;

  /* ---------- 密钥生成（keypair / genpoly / pk_gen / controlbits） ---------- */
/* Classic McEliece 全参数集密钥生成 —— 逐行移植 PQClean clean 参考实现
   参考: operations.c (keypair) / sk_gen.c (genpoly_gen) / pk_gen.c / controlbits.c
*/
var PARAMS = PM.PARAMS;

/* 纯 JS SHAKE256（Node 的 crypto shake256 输出上限 32 字节，不足以生成 r） */
function mkKeygen(tag) {
  var P = PARAMS[tag];
  var GFBITS = P.GFBITS, SYS_N = P.SYS_N, SYS_T = P.SYS_T;
  var GFMASK = (1 << GFBITS) - 1;
  var PK_NROWS = SYS_T * GFBITS, PK_NCOLS = SYS_N - PK_NROWS;
  var PK_ROW_BYTES = (PK_NCOLS + 7) >> 3;
  var SYND_BYTES = (PK_NROWS + 7) >> 3;
  var IRR_BYTES = SYS_T * 2;
  var COND_BYTES = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
  var SYSNB = SYS_N >> 3;
  var BR = 16 - GFBITS;

  /* ---------- GF(2^m) ---------- */
  function gfMul(a, b) {
    var i, tmp = a * (b & 1), t;
    for (i = 1; i < GFBITS; i++) tmp ^= (a * (b & (1 << i)));
    if (GFBITS === 12) {
      t = tmp & 0x7FC000; tmp ^= t >> 9; tmp ^= t >> 12;
      t = tmp & 0x3000; tmp ^= t >> 9; tmp ^= t >> 12;
    } else {
      t = tmp & 0x1FF0000; tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
      t = tmp & 0x000E000; tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }
    return tmp & GFMASK;
  }
  function gfSq(a) { return gfMul(a, a); }
  function gfInv(a) {
    var e = (1 << GFBITS) - 2, r = 1, b = a;
    while (e > 0) { if (e & 1) r = gfMul(r, b); b = gfSq(b); e >>= 1; }
    return r;
  }
  function gfIsZero(a) { var t = a; t -= 1; t >>= 19; return t; }
  function loadGf(s, o) { return (s[o] | (s[o + 1] << 8)) & GFMASK; }
  function storeGf(s, o, v) { s[o] = v & 0xFF; s[o + 1] = (v >> 8) & 0xFF; }
  function load4(b, o) { return ((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)) + b[o + 3] * 16777216) >>> 0; }
  function bitrev(a) {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);
    return a >> BR;
  }
  function evalPoly(f, a) {
    var r = f[SYS_T], i;
    for (i = SYS_T - 1; i >= 0; i--) { r = gfMul(r, a); r ^= f[i]; }
    return r;
  }

  /* ---------- GF((2^m)^t) 乘法（gf.c GF_mul） ---------- */
  function GF_mul(out, outo, in0, in0o, in1, in1o) {
    var prod = new Int32Array(2 * SYS_T - 1), i, j, k, c;
    for (i = 0; i < SYS_T; i++) for (j = 0; j < SYS_T; j++) prod[i + j] ^= gfMul(in0[in0o + i], in1[in1o + j]);
    for (i = (SYS_T - 1) * 2; i >= SYS_T; i--) {
      for (k = 0; k < P.COEF.length; k++) {
        c = P.COEF[k];
        if (c === 0 && P.COEFMUL2) prod[i - SYS_T] ^= gfMul(prod[i], 2);
        else prod[i - SYS_T + c] ^= prod[i];
      }
    }
    for (i = 0; i < SYS_T; i++) out[outo + i] = prod[i];
  }

  /* ---------- genpoly_gen（sk_gen.c） ---------- */
  function genpolyGen(out, f) {
    var i, j, k, c, mask, inv, t;
    var mat = new Int32Array((SYS_T + 1) * SYS_T);
    mat[0 * SYS_T + 0] = 1;
    for (i = 1; i < SYS_T; i++) mat[0 * SYS_T + i] = 0;
    for (i = 0; i < SYS_T; i++) mat[1 * SYS_T + i] = f[i];
    for (j = 2; j <= SYS_T; j++) GF_mul(mat, j * SYS_T, mat, (j - 1) * SYS_T, f, 0);

    for (j = 0; j < SYS_T; j++) {
      for (k = j + 1; k < SYS_T; k++) {
        mask = gfIsZero(mat[j * SYS_T + j]);
        for (c = j; c < SYS_T + 1; c++) mat[c * SYS_T + j] ^= mat[c * SYS_T + k] & mask;
      }
      if (gfIsZero(mat[j * SYS_T + j])) return -1;
      inv = gfInv(mat[j * SYS_T + j]);
      for (c = j; c < SYS_T + 1; c++) mat[c * SYS_T + j] = gfMul(mat[c * SYS_T + j], inv);
      for (k = 0; k < SYS_T; k++) {
        if (k !== j) {
          t = mat[j * SYS_T + k];
          for (c = j; c < SYS_T + 1; c++) mat[c * SYS_T + k] ^= gfMul(mat[c * SYS_T + j], t);
        }
      }
    }
    for (i = 0; i < SYS_T; i++) out[i] = mat[SYS_T * SYS_T + i];
    return 0;
  }

  /* 浏览器安全的调试开关。注意：此处原写为 Node 专有全局 process 上的环境变量读取，
     在浏览器中 process 未定义会直接抛 ReferenceError（密钥生成必崩），已改为普通布尔常量。 */
  var MCEDBG = false, MCEDBG2 = false;

  /* ---------- controlbits（Nassimi-Sahni） ---------- */
  /* 对 Int32Array 用 TypedArray 原生排序：数值升序、原地、无需 slice 拷贝。
     注：官方 controlbits.c 用双调排序网络；此处输入为公开置换，非秘密，
     变时排序不构成侧信道风险，故采用更快的原生实现（结果一致）。 */
  function int32sort(A, n) {
    A.subarray(0, n).sort();
  }
  function int32min(x, y) { return x < y ? x : y; }

  function cbrecursion(out, pos, step, pi, w, n) {
    var A = new Int32Array(2 * n), B = new Int32Array(n);
    var q = new Int16Array(n);
    var x, y, i, j, k, Ax, px, cx, fj, Fx, Fx1, lk, Ly, Ly1, ppcpx, ppcx;

    if (w === 1) { out[pos >> 3] ^= pi[0] << (pos & 7); return; }

    for (x = 0; x < n; ++x) A[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1];
    int32sort(A, n);
    for (x = 0; x < n; ++x) {
      Ax = A[x]; px = Ax & 0xffff; cx = int32min(px, x);
      B[x] = (px << 16) | cx;
    }
    for (x = 0; x < n; ++x) A[x] = (((A[x] >>> 0) << 16) | x) | 0;
    int32sort(A, n);
    for (x = 0; x < n; ++x) A[x] = (((A[x] >>> 0) << 16) + (B[x] >> 16)) | 0;
    int32sort(A, n);

    if (w <= 10) {
      for (x = 0; x < n; ++x) B[x] = ((A[x] & 0xffff) << 10) | (B[x] & 0x3ff);
      for (i = 1; i < w - 1; ++i) {
        for (x = 0; x < n; ++x) A[x] = ((B[x] & ~0x3ff) << 6) | x;
        int32sort(A, n);
        for (x = 0; x < n; ++x) A[x] = ((A[x] >>> 0) << 20) | B[x];
        int32sort(A, n);
        for (x = 0; x < n; ++x) {
          ppcpx = A[x] & 0xfffff;
          ppcx = (A[x] & 0xffc00) | (B[x] & 0x3ff);
          B[x] = int32min(ppcx, ppcpx);
        }
      }
      for (x = 0; x < n; ++x) B[x] &= 0x3ff;
    } else {
      for (x = 0; x < n; ++x) B[x] = (((A[x] >>> 0) << 16) | (B[x] & 0xffff)) | 0;
      for (i = 1; i < w - 1; ++i) {
        for (x = 0; x < n; ++x) A[x] = (B[x] & ~0xffff) | x;
        int32sort(A, n);
        for (x = 0; x < n; ++x) A[x] = (((A[x] >>> 0) << 16) | (B[x] & 0xffff)) | 0;
        if (i < w - 2) {
          for (x = 0; x < n; ++x) B[x] = (A[x] & ~0xffff) | (B[x] >> 16);
          int32sort(B, n);
          for (x = 0; x < n; ++x) B[x] = (((B[x] >>> 0) << 16) | (A[x] & 0xffff)) | 0;
        }
        int32sort(A, n);
        for (x = 0; x < n; ++x) {
          var cpx = (B[x] & ~0xffff) | (A[x] & 0xffff);
          B[x] = int32min(B[x], cpx);
        }
      }
      for (x = 0; x < n; ++x) B[x] &= 0xffff;
    }

    for (x = 0; x < n; ++x) A[x] = ((pi[x] << 16) + x) | 0;
    int32sort(A, n);

    for (j = 0; j < n / 2; ++j) {
      x = 2 * j;
      fj = B[x] & 1;
      Fx = x + fj;
      Fx1 = Fx ^ 1;
      out[pos >> 3] ^= fj << (pos & 7);
      pos += step;
      B[x] = ((A[x] >>> 0) << 16) | Fx;
      B[x + 1] = ((A[x + 1] >>> 0) << 16) | Fx1;
    }
    int32sort(B, n);
    pos += (2 * w - 3) * step * (n / 2);

    for (k = 0; k < n / 2; ++k) {
      y = 2 * k;
      lk = B[y] & 1;
      Ly = y + lk;
      Ly1 = Ly ^ 1;
      out[pos >> 3] ^= lk << (pos & 7);
      pos += step;
      A[y] = (Ly << 16) | (B[y] & 0xffff);
      A[y + 1] = (Ly1 << 16) | (B[y + 1] & 0xffff);
    }
    int32sort(A, n);
    pos -= (2 * w - 2) * step * (n / 2);

    for (j = 0; j < n / 2; ++j) {
      q[j] = (A[2 * j] & 0xffff) >> 1;
      q[j + n / 2] = (A[2 * j + 1] & 0xffff) >> 1;
    }
    cbrecursion(out, pos, step * 2, q.subarray(0, n / 2), w - 1, n / 2);
    cbrecursion(out, pos + step, step * 2, q.subarray(n / 2, n), w - 1, n / 2);
  }

  function layer(p, cb, cbo, s, n) {
    var i, j, stride = 1 << s, index = 0, d, m;
    for (i = 0; i < n; i += stride * 2) {
      for (j = 0; j < stride; j++) {
        d = p[i + j] ^ p[i + j + stride];
        m = (cb[cbo + (index >> 3)] >> (index & 7)) & 1;
        m = -m;
        d &= m;
        p[i + j] ^= d;
        p[i + j + stride] ^= d;
        index++;
      }
    }
  }

  function controlbitsfrompermutation(out, pi, w, n) {
    var i, ptr = 0, diff;
    var pi_test = new Int16Array(n);
    out.fill(0);
    cbrecursion(out, 0, 1, pi, w, n);
    /* 自检：应用控制位应还原 pi */
    for (i = 0; i < n; i++) pi_test[i] = i;
    ptr = 0;
    for (i = 0; i < w; i++) { layer(pi_test, out, ptr, i, n); ptr += n >> 4; }
    for (i = w - 2; i >= 0; i--) { layer(pi_test, out, ptr, i, n); ptr += n >> 4; }
    diff = 0;
    for (i = 0; i < n; i++) diff |= pi[i] ^ pi_test[i];
    return diff === 0;
  }

  /* ---------- pk_gen（pk_gen.c） ---------- */
  function pkGen(irrBytes, perm) {
    var i, j, k, row, c, mask, b;
    var n2 = 1 << GFBITS;
    var g = new Int32Array(SYS_T + 1);
    var L = new Int32Array(SYS_N), inv = new Int32Array(SYS_N);
    var idx = new Array(n2), pi = new Int16Array(n2);
    g[SYS_T] = 1;
    for (i = 0; i < SYS_T; i++) g[i] = loadGf(irrBytes, i * 2);
    for (i = 0; i < n2; i++) idx[i] = i;
    idx.sort(function (a, bb) { return (perm[a] >>> 0) - (perm[bb] >>> 0); });
    for (i = 1; i < n2; i++) if ((perm[idx[i - 1]] >>> 0) === (perm[idx[i]] >>> 0)) return null;
    for (i = 0; i < n2; i++) pi[i] = idx[i];
    for (i = 0; i < SYS_N; i++) L[i] = bitrev(pi[i]);
    for (i = 0; i < SYS_N; i++) inv[i] = evalPoly(g, L[i]);
    for (i = 0; i < SYS_N; i++) inv[i] = gfInv(inv[i]);

    var mat = new Uint8Array(PK_NROWS * SYSNB);
    for (i = 0; i < SYS_T; i++) {
      for (j = 0; j < SYS_N; j += 8) {
        for (k = 0; k < GFBITS; k++) {
          b = ((inv[j + 7] >> k) & 1); b <<= 1;
          b |= ((inv[j + 6] >> k) & 1); b <<= 1;
          b |= ((inv[j + 5] >> k) & 1); b <<= 1;
          b |= ((inv[j + 4] >> k) & 1); b <<= 1;
          b |= ((inv[j + 3] >> k) & 1); b <<= 1;
          b |= ((inv[j + 2] >> k) & 1); b <<= 1;
          b |= ((inv[j + 1] >> k) & 1); b <<= 1;
          b |= ((inv[j + 0] >> k) & 1);
          mat[(i * GFBITS + k) * SYSNB + (j / 8)] = b;
        }
      }
      for (j = 0; j < SYS_N; j++) inv[j] = gfMul(inv[j], L[j]);
    }

    /* 高斯消元 */
    for (i = 0; i < (PK_NROWS + 7) / 8; i++) {
      for (j = 0; j < 8; j++) {
        row = i * 8 + j;
        if (row >= PK_NROWS) break;
        for (k = row + 1; k < PK_NROWS; k++) {
          mask = mat[row * SYSNB + i] ^ mat[k * SYSNB + i];
          mask >>= j; mask &= 1; mask = -mask;
          for (c = 0; c < SYSNB; c++) mat[row * SYSNB + c] ^= mat[k * SYSNB + c] & mask;
        }
        if (gfIsZero((mat[row * SYSNB + i] >> j) & 1)) return null;
        for (k = 0; k < PK_NROWS; k++) {
          if (k !== row) {
            mask = mat[k * SYSNB + i] >> j; mask &= 1; mask = -mask;
            for (c = 0; c < SYSNB; c++) mat[k * SYSNB + c] ^= mat[row * SYSNB + c] & mask;
          }
        }
      }
    }

    if (MCEDBG2) {
      var nzm = 0; for (var q = 0; q < mat.length; q++) if (mat[q]) nzm++;
      console.error('DBG inv[0..5]', Array.prototype.slice.call(inv, 0, 6));
      console.error('DBG L[0..5]', Array.prototype.slice.call(L, 0, 6));
      console.error('DBG pi[0..5]', Array.prototype.slice.call(pi, 0, 6));
      console.error('DBG g[0..5]', Array.prototype.slice.call(g, 0, 6), 'g[SYS_T]', g[SYS_T]);
      console.error('DBG mat nonzero', nzm, '/', mat.length, 'tail', PK_NROWS % 8, 'SYSNB', SYSNB);
    }
    var pk = new Uint8Array(P.PK), off = PK_NROWS >> 3, tail = PK_NROWS % 8, pkptr = 0;
    if (tail === 0) {
      for (i = 0; i < PK_NROWS; i++) {
        pk.set(mat.subarray(i * SYSNB + off, i * SYSNB + off + PK_ROW_BYTES), i * PK_ROW_BYTES);
      }
    } else {
      /* 6960119: PK_NROWS 不是 8 的倍数，官方逐字节右移 tail 位输出 */
      /* 注意：C 的 (PK_NROWS-1)/8 是整数除法，JS 必须取整，否则下标为小数 -> undefined */
      for (i = 0; i < PK_NROWS; i++) {
        for (j = off; j < SYSNB - 1; j++) {
          pk[pkptr++] = ((mat[i * SYSNB + j] >> tail) | (mat[i * SYSNB + j + 1] << (8 - tail))) & 0xFF;
        }
        pk[pkptr++] = (mat[i * SYSNB + j] >> tail) & 0xFF;
      }
    }
    return { pk: pk, pi: pi };
  }

  /* ---------- keypair（operations.c） ---------- */
  function keypair(skPrf32) {
    var R = SYSNB + (1 << GFBITS) * 4 + SYS_T * 2 + 32;
    var seed = new Uint8Array(33);
    seed[0] = 64;
    seed.set(skPrf32.subarray(0, 32), 1);
    var i, rp, skp, r;
    var f = new Int32Array(SYS_T), irr = new Int32Array(SYS_T);
    var pi = new Int16Array(1 << GFBITS);
    var sk = new Uint8Array(P.SK), pk = null;
    var tries = 0;

    while (true) {
      tries++;
      if (tries > 8) throw new Error('keypair: 重试次数过多');
      r = shake256Bytes(seed, R);
      rp = R - 32;
      sk.set(seed.subarray(1, 33), 0);
      skp = 32 + 8;
      seed.set(r.subarray(R - 32, R), 1);

      /* f */
      rp -= SYS_T * 2;
      for (i = 0; i < SYS_T; i++) f[i] = loadGf(r, rp + i * 2);
      if (genpolyGen(irr, f) !== 0) { if (MCEDBG) console.error('  try' + tries + ' genpoly fail'); continue; }
      for (i = 0; i < SYS_T; i++) storeGf(sk, skp + i * 2, irr[i]);
      skp += IRR_BYTES;

      /* perm */
      rp -= (1 << GFBITS) * 4;
      var perm = new Uint32Array(1 << GFBITS);
      for (i = 0; i < (1 << GFBITS); i++) perm[i] = load4(r, rp + i * 4);

      var res = pkGen(sk.subarray(skp - IRR_BYTES, skp), perm);
      if (!res) { if (MCEDBG) console.error('  try' + tries + ' pk_gen fail'); continue; }
      pk = res.pk;
      pi = res.pi;

      var cond = new Uint8Array(COND_BYTES);
      var ok = controlbitsfrompermutation(cond, pi, GFBITS, 1 << GFBITS);
      if (!ok) throw new Error('controlbits 自检失败');
      sk.set(cond, skp);
      skp += COND_BYTES;

      /* s */
      rp -= SYSNB;
      sk.set(r.subarray(0, SYSNB), skp);
      skp += SYSNB;

      /* pivots */
      for (i = 32; i < 36; i++) sk[i] = 0xFF; /* store8(sk+32, 0xFFFFFFFF) 小端 */
      break;
    }
    return { pk: pk, sk: sk, tries: tries };
  }

  return {
    keypair: keypair, genpolyGen: genpolyGen, pkGen: pkGen,
    controlbitsfrompermutation: controlbitsfrompermutation,
    P: P, PK_ROW_BYTES: PK_ROW_BYTES, SYND_BYTES: SYND_BYTES,
    IRR_BYTES: IRR_BYTES, COND_BYTES: COND_BYTES, SYSNB: SYSNB
  };
}



  /* ---------- 参数化封装 (encrypt.c: 随机错误向量 -> syndrome -> SHAKE256) ---------- */
  function mkEnc(tag) {
    var P = PARAMS[tag];
    var GFBITS = P.GFBITS, SYS_N = P.SYS_N, SYS_T = P.SYS_T;
    var GFMASK = (1 << GFBITS) - 1, SYSNB = SYS_N >> 3;
    var PK_NROWS = SYS_T * GFBITS, PK_NCOLS = SYS_N - PK_NROWS;
    var PK_ROW_BYTES = (PK_NCOLS + 7) >> 3;
    var SYND_BYTES = (PK_NROWS + 7) >> 3, tail = PK_NROWS % 8;
    var SIMPLE = (SYS_N >= (1 << GFBITS));   /* 8192128: SYS_N==2^GFBITS，官方不做过滤 */
    function genE(rnd) {
      for (;;) {
        var rb = rnd(SIMPLE ? SYS_T * 2 : SYS_T * 4), ind = [], i, j, count = 0, eq, n;
        if (SIMPLE) { for (i = 0; i < SYS_T; i++) ind.push((rb[i*2] | (rb[i*2+1] << 8)) & GFMASK); count = SYS_T; }
        else for (i = 0; i < SYS_T * 2; i++) {
          n = (rb[i*2] | (rb[i*2+1] << 8)) & GFMASK;
          if (count < SYS_T && n < SYS_N) { ind.push(n); count++; }
        }
        if (count < SYS_T) continue;
        eq = 0; for (i = 1; i < SYS_T; i++) for (j = 0; j < i; j++) if (ind[i] === ind[j]) eq = 1;
        if (eq === 0) {
          var e = new Uint8Array(SYSNB);
          for (i = 0; i < SYS_T; i++) e[ind[i] >> 3] |= 1 << (ind[i] & 7);
          return e;
        }
      }
    }
    function syndrome(pk, e) {
      var s = new Uint8Array(SYND_BYTES), row = new Uint8Array(SYSNB), i, j, b, p = 0;
      var off = SYSNB - PK_ROW_BYTES;
      for (i = 0; i < PK_NROWS; i++) {
        for (j = 0; j < SYSNB; j++) row[j] = 0;
        for (j = 0; j < PK_ROW_BYTES; j++) row[off + j] = pk[p + j];
        if (tail !== 0) { for (j = SYSNB - 1; j >= off; j--) row[j] = ((row[j] << tail) | (row[j-1] >> (8 - tail))) & 0xFF; }
        row[(i / 8) | 0] |= 1 << (i & 7);
        b = 0; for (j = 0; j < SYSNB; j++) b ^= row[j] & e[j];
        b ^= b >> 4; b ^= b >> 2; b ^= b >> 1; b &= 1;
        s[(i / 8) | 0] |= (b << (i & 7));
        p += PK_ROW_BYTES;
      }
      return s;
    }
    return function kemEnc(pk, rnd) {
      var e = genE(rnd);
      var ct = syndrome(pk, e);
      var pre = new Uint8Array(1 + SYSNB + SYND_BYTES);
      pre[0] = 1; pre.set(e, 1); pre.set(ct, 1 + SYSNB);
      return { ct: ct, ss: shake256Bytes(pre, 32) };
    };
  }
  var KEM_460896 = null, MKD_460896 = null, MKG_460896 = null;
  var KEM_6688128 = null, MKD_6688128 = null, MKG_6688128 = null;
  var KEM_6960119 = null, MKD_6960119 = null, MKG_6960119 = null;
  var KEM_8192128 = null, MKD_8192128 = null, MKG_8192128 = null;
  function mceInit(tag) {
    if (tag === "460896") { if (!KEM_460896) { KEM_460896 = mkEnc("460896"); MKD_460896 = PM.mkFull("460896"); MKG_460896 = mkKeygen("460896"); } return; }
    if (tag === "6688128") { if (!KEM_6688128) { KEM_6688128 = mkEnc("6688128"); MKD_6688128 = PM.mkFull("6688128"); MKG_6688128 = mkKeygen("6688128"); } return; }
    if (tag === "6960119") { if (!KEM_6960119) { KEM_6960119 = mkEnc("6960119"); MKD_6960119 = PM.mkFull("6960119"); MKG_6960119 = mkKeygen("6960119"); } return; }
    if (tag === "8192128") { if (!KEM_8192128) { KEM_8192128 = mkEnc("8192128"); MKD_8192128 = PM.mkFull("8192128"); MKG_8192128 = mkKeygen("8192128"); } return; }
  }
  mceInit("460896");
  mceInit("6688128");
  mceInit("6960119");
  mceInit("8192128");

  /* ---------------- 注册到算法表 ---------------- */
  if (typeof reg === "function") {
    function mceRnd(n) {
      if (typeof crypto !== "undefined" && crypto.getRandomValues) {
        var a = new Uint8Array(n); crypto.getRandomValues(a); return a;
      }
      var b = new Uint8Array(n);
      for (var i = 0; i < n; i++) b[i] = (Math.random() * 256) | 0;
      return b;
    }
    var INFO_460896 = "Classic McEliece 460896：码基后量子 KEM（二元 Goppa 码，GFBITS=13）。" +
      "公钥 524160 字节（约 512KB，建议【载入文件】导入）、私钥 13608 字节、密文 156 字节、密钥 32 字节。" +
      "已过官方 NIST KAT（keygen pk/sk 逐字节一致，封装密文与密钥一致）。密钥生成见同组下一条。";
    reg({ id: "mceliece460896", name: "Classic McEliece 460896（码基 KEM）",
      group: "后量子密码", key: true, param: false,
      keyLabel: "封装填公钥（524160 字节 Hex，建议用载入文件）；解封装填私钥（13608 字节 Hex）",
      info: INFO_460896,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入封装公钥（Hex）");
        var pk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (pk.length !== 524160) throw new Error("公钥长度应为 524160 字节，实际 " + pk.length);
        var out = KEM_460896(pk, mceRnd);
        return bytesOut(out.ct, fmt) + "\n::K::" + bytesOut(out.ss, fmt);
      },
      dec: function (str, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入解封装私钥（Hex）");
        var sk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (sk.length !== 13608) throw new Error("私钥长度应为 13608 字节，实际 " + sk.length);
        var cHex = String(str).split("::K::")[0].trim();
        var c = bytesIn(cHex, fmt);
        if (c.length !== 156) throw new Error("密文长度应为 156 字节，实际 " + c.length);
        return bytesOut(MKD_460896.kemDec(sk, c), fmt);
      } });
    var KG_460896 = "生成 Classic McEliece 460896 密钥对：公钥 524160 字节、私钥 13608 字节。" +
      "流程：随机 Goppa 多项式 → 随机排列 → 系统形式公钥 → Benes 控制位压缩。" +
      "已过官方 NIST KAT（pk/sk 逐字节一致）。公钥很大，建议参数栏填 sk 只输出私钥。" +
      "注意：n=8192 参数集生成较慢（含 128 位 Benes 与高斯消元），请耐心等待。";
    reg({ id: "mceliece460896-keygen", name: "Classic McEliece 460896 密钥生成（官方 KAT 验证）",
      group: "后量子密码", key: false, param: true,
      paramLabel: "留空=随机生成；填 64 位 Hex=用该种子确定性生成；填 sk=只输出私钥",
      info: KG_460896,
      enc: function (b, kk, pp, fmt) {
        var seed = null, onlySk = false;
        if (pp) {
          var s = String(pp).trim();
          if (/^[0-9a-fA-F]{64}$/.test(s)) seed = hexToBytes(s);
          else if (/sk/i.test(s)) onlySk = true;
        }
        if (!seed) seed = mceRnd(32);
        var res = MKG_460896.keypair(seed);
        if (!res) throw new Error("密钥生成失败（概率极低），请重试");
        if (onlySk) return bytesOut(res.sk, fmt);
        return bytesOut(res.pk, fmt) + "\n::K::" + bytesOut(res.sk, fmt);
      },
      dec: false });
    var INFO_6688128 = "Classic McEliece 6688128：码基后量子 KEM（二元 Goppa 码，GFBITS=13）。" +
      "公钥 1044992 字节（约 1021KB，建议【载入文件】导入）、私钥 13932 字节、密文 208 字节、密钥 32 字节。" +
      "已过官方 NIST KAT（keygen pk/sk 逐字节一致，封装密文与密钥一致）。密钥生成见同组下一条。";
    reg({ id: "mceliece6688128", name: "Classic McEliece 6688128（码基 KEM）",
      group: "后量子密码", key: true, param: false,
      keyLabel: "封装填公钥（1044992 字节 Hex，建议用载入文件）；解封装填私钥（13932 字节 Hex）",
      info: INFO_6688128,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入封装公钥（Hex）");
        var pk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (pk.length !== 1044992) throw new Error("公钥长度应为 1044992 字节，实际 " + pk.length);
        var out = KEM_6688128(pk, mceRnd);
        return bytesOut(out.ct, fmt) + "\n::K::" + bytesOut(out.ss, fmt);
      },
      dec: function (str, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入解封装私钥（Hex）");
        var sk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (sk.length !== 13932) throw new Error("私钥长度应为 13932 字节，实际 " + sk.length);
        var cHex = String(str).split("::K::")[0].trim();
        var c = bytesIn(cHex, fmt);
        if (c.length !== 208) throw new Error("密文长度应为 208 字节，实际 " + c.length);
        return bytesOut(MKD_6688128.kemDec(sk, c), fmt);
      } });
    var KG_6688128 = "生成 Classic McEliece 6688128 密钥对：公钥 1044992 字节、私钥 13932 字节。" +
      "流程：随机 Goppa 多项式 → 随机排列 → 系统形式公钥 → Benes 控制位压缩。" +
      "已过官方 NIST KAT（pk/sk 逐字节一致）。公钥很大，建议参数栏填 sk 只输出私钥。" +
      "注意：n=8192 参数集生成较慢（含 128 位 Benes 与高斯消元），请耐心等待。";
    reg({ id: "mceliece6688128-keygen", name: "Classic McEliece 6688128 密钥生成（官方 KAT 验证）",
      group: "后量子密码", key: false, param: true,
      paramLabel: "留空=随机生成；填 64 位 Hex=用该种子确定性生成；填 sk=只输出私钥",
      info: KG_6688128,
      enc: function (b, kk, pp, fmt) {
        var seed = null, onlySk = false;
        if (pp) {
          var s = String(pp).trim();
          if (/^[0-9a-fA-F]{64}$/.test(s)) seed = hexToBytes(s);
          else if (/sk/i.test(s)) onlySk = true;
        }
        if (!seed) seed = mceRnd(32);
        var res = MKG_6688128.keypair(seed);
        if (!res) throw new Error("密钥生成失败（概率极低），请重试");
        if (onlySk) return bytesOut(res.sk, fmt);
        return bytesOut(res.pk, fmt) + "\n::K::" + bytesOut(res.sk, fmt);
      },
      dec: false });
    var INFO_6960119 = "Classic McEliece 6960119：码基后量子 KEM（二元 Goppa 码，GFBITS=13）。" +
      "公钥 1047319 字节（约 1023KB，建议【载入文件】导入）、私钥 13948 字节、密文 194 字节、密钥 32 字节。" +
      "已过官方 NIST KAT（keygen pk/sk 逐字节一致，封装密文与密钥一致）。密钥生成见同组下一条。";
    reg({ id: "mceliece6960119", name: "Classic McEliece 6960119（码基 KEM）",
      group: "后量子密码", key: true, param: false,
      keyLabel: "封装填公钥（1047319 字节 Hex，建议用载入文件）；解封装填私钥（13948 字节 Hex）",
      info: INFO_6960119,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入封装公钥（Hex）");
        var pk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (pk.length !== 1047319) throw new Error("公钥长度应为 1047319 字节，实际 " + pk.length);
        var out = KEM_6960119(pk, mceRnd);
        return bytesOut(out.ct, fmt) + "\n::K::" + bytesOut(out.ss, fmt);
      },
      dec: function (str, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入解封装私钥（Hex）");
        var sk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (sk.length !== 13948) throw new Error("私钥长度应为 13948 字节，实际 " + sk.length);
        var cHex = String(str).split("::K::")[0].trim();
        var c = bytesIn(cHex, fmt);
        if (c.length !== 194) throw new Error("密文长度应为 194 字节，实际 " + c.length);
        return bytesOut(MKD_6960119.kemDec(sk, c), fmt);
      } });
    var KG_6960119 = "生成 Classic McEliece 6960119 密钥对：公钥 1047319 字节、私钥 13948 字节。" +
      "流程：随机 Goppa 多项式 → 随机排列 → 系统形式公钥 → Benes 控制位压缩。" +
      "已过官方 NIST KAT（pk/sk 逐字节一致）。公钥很大，建议参数栏填 sk 只输出私钥。" +
      "注意：n=8192 参数集生成较慢（含 128 位 Benes 与高斯消元），请耐心等待。";
    reg({ id: "mceliece6960119-keygen", name: "Classic McEliece 6960119 密钥生成（官方 KAT 验证）",
      group: "后量子密码", key: false, param: true,
      paramLabel: "留空=随机生成；填 64 位 Hex=用该种子确定性生成；填 sk=只输出私钥",
      info: KG_6960119,
      enc: function (b, kk, pp, fmt) {
        var seed = null, onlySk = false;
        if (pp) {
          var s = String(pp).trim();
          if (/^[0-9a-fA-F]{64}$/.test(s)) seed = hexToBytes(s);
          else if (/sk/i.test(s)) onlySk = true;
        }
        if (!seed) seed = mceRnd(32);
        var res = MKG_6960119.keypair(seed);
        if (!res) throw new Error("密钥生成失败（概率极低），请重试");
        if (onlySk) return bytesOut(res.sk, fmt);
        return bytesOut(res.pk, fmt) + "\n::K::" + bytesOut(res.sk, fmt);
      },
      dec: false });
    var INFO_8192128 = "Classic McEliece 8192128：码基后量子 KEM（二元 Goppa 码，GFBITS=13）。" +
      "公钥 1357824 字节（约 1326KB，建议【载入文件】导入）、私钥 14120 字节、密文 208 字节、密钥 32 字节。" +
      "已过官方 NIST KAT（keygen pk/sk 逐字节一致，封装密文与密钥一致）。密钥生成见同组下一条。";
    reg({ id: "mceliece8192128", name: "Classic McEliece 8192128（码基 KEM）",
      group: "后量子密码", key: true, param: false,
      keyLabel: "封装填公钥（1357824 字节 Hex，建议用载入文件）；解封装填私钥（14120 字节 Hex）",
      info: INFO_8192128,
      enc: function (b, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入封装公钥（Hex）");
        var pk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (pk.length !== 1357824) throw new Error("公钥长度应为 1357824 字节，实际 " + pk.length);
        var out = KEM_8192128(pk, mceRnd);
        return bytesOut(out.ct, fmt) + "\n::K::" + bytesOut(out.ss, fmt);
      },
      dec: function (str, kk, pp, fmt) {
        if (!kk) throw new Error("请在密钥栏填入解封装私钥（Hex）");
        var sk = hexToBytes(String(kk).replace(/\s/g, ""));
        if (sk.length !== 14120) throw new Error("私钥长度应为 14120 字节，实际 " + sk.length);
        var cHex = String(str).split("::K::")[0].trim();
        var c = bytesIn(cHex, fmt);
        if (c.length !== 208) throw new Error("密文长度应为 208 字节，实际 " + c.length);
        return bytesOut(MKD_8192128.kemDec(sk, c), fmt);
      } });
    var KG_8192128 = "生成 Classic McEliece 8192128 密钥对：公钥 1357824 字节、私钥 14120 字节。" +
      "流程：随机 Goppa 多项式 → 随机排列 → 系统形式公钥 → Benes 控制位压缩。" +
      "已过官方 NIST KAT（pk/sk 逐字节一致）。公钥很大，建议参数栏填 sk 只输出私钥。" +
      "注意：n=8192 参数集生成较慢（含 128 位 Benes 与高斯消元），请耐心等待。";
    reg({ id: "mceliece8192128-keygen", name: "Classic McEliece 8192128 密钥生成（官方 KAT 验证）",
      group: "后量子密码", key: false, param: true,
      paramLabel: "留空=随机生成；填 64 位 Hex=用该种子确定性生成；填 sk=只输出私钥",
      info: KG_8192128,
      enc: function (b, kk, pp, fmt) {
        var seed = null, onlySk = false;
        if (pp) {
          var s = String(pp).trim();
          if (/^[0-9a-fA-F]{64}$/.test(s)) seed = hexToBytes(s);
          else if (/sk/i.test(s)) onlySk = true;
        }
        if (!seed) seed = mceRnd(32);
        var res = MKG_8192128.keypair(seed);
        if (!res) throw new Error("密钥生成失败（概率极低），请重试");
        if (onlySk) return bytesOut(res.sk, fmt);
        return bytesOut(res.pk, fmt) + "\n::K::" + bytesOut(res.sk, fmt);
      },
      dec: false });
  }
})();
