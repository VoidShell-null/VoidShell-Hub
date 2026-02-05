type HashFunction__DARKLUA_TYPE_a=(...any)->(string,buffer)

type EntropyProvider__DARKLUA_TYPE_b=(BytesLeft:number)->buffer?

type CSPRNGModule__DARKLUA_TYPE_c={
BlockExpansion:boolean,

SizeTarget:number,
RekeyAfter:number,

Key:buffer,
Nonce:buffer,
Buffer:buffer,

Counter:number,
BufferPosition:number,
BufferSize:number,
BytesLeft:number,

EntropyProviders:{EntropyProvider__DARKLUA_TYPE_b},

Reseed:(CustomEntropy:buffer?)->(),
AddEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_b)->(),
RemoveEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_b)->(),

Random:()->number,
RandomInt:(Min:number,Max:number?)->number,
RandomNumber:(Min:number,Max:number?)->number,
RandomBytes:(Count:number)->buffer,
RandomString:(Length:number,AsBuffer:boolean?)->string|buffer,
RandomHex:(Length:number)->string,
Ed25519ClampedBytes:(Input:buffer)->buffer,
Ed25519Random:()->buffer,
}

type Processor__DARKLUA_TYPE_d=(PlaintextBlock:buffer,PlaintextOffset:number,OutputBuffer:buffer,OutputOffset:number)->()

type EntropyProvider__DARKLUA_TYPE_e=(BytesLeft:number)->buffer?

type CSPRNGModule__DARKLUA_TYPE_f={
BlockExpansion:boolean,

SizeTarget:number,
RekeyAfter:number,

Key:buffer,
Nonce:buffer,
Buffer:buffer,

Counter:number,
BufferPosition:number,
BufferSize:number,
BytesLeft:number,

EntropyProviders:{EntropyProvider__DARKLUA_TYPE_e},

Reseed:(CustomEntropy:buffer?)->(),
AddEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_e)->(),
RemoveEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_e)->(),

Random:()->number,
RandomInt:(Min:number,Max:number?)->number,
RandomNumber:(Min:number,Max:number?)->number,
RandomBytes:(Count:number)->buffer,
RandomString:(Length:number,AsBuffer:boolean?)->string|buffer,
RandomHex:(Length:number)->string,
Ed25519ClampedBytes:(Input:buffer)->buffer,
Ed25519Random:()->buffer,
}

type SignatureEntry__DARKLUA_TYPE_g={
PublicKey:buffer,
Message:buffer,
Signature:buffer,
}

type EntropyProvider__DARKLUA_TYPE_h=(BytesLeft:number)->buffer?

type CSPRNGModule__DARKLUA_TYPE_i={
BlockExpansion:boolean,

SizeTarget:number,
RekeyAfter:number,

Key:buffer,
Nonce:buffer,
Buffer:buffer,

Counter:number,
BufferPosition:number,
BufferSize:number,
BytesLeft:number,

EntropyProviders:{EntropyProvider__DARKLUA_TYPE_h},

Reseed:(CustomEntropy:buffer?)->(),
AddEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_h)->(),
RemoveEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_h)->(),

Random:()->number,
RandomInt:(Min:number,Max:number?)->number,
RandomNumber:(Min:number,Max:number?)->number,
RandomBytes:(Count:number)->buffer,
RandomString:(Length:number,AsBuffer:boolean?)->string|buffer,
RandomHex:(Length:number)->string,
Ed25519ClampedBytes:(Input:buffer)->buffer,
Ed25519Random:()->buffer,
}

type EntropyProvider__DARKLUA_TYPE_j=(BytesLeft:number)->buffer?

type CSPRNGModule__DARKLUA_TYPE_k={
BlockExpansion:boolean,

SizeTarget:number,
RekeyAfter:number,

Key:buffer,
Nonce:buffer,
Buffer:buffer,

Counter:number,
BufferPosition:number,
BufferSize:number,
BytesLeft:number,

EntropyProviders:{EntropyProvider__DARKLUA_TYPE_j},

Reseed:(CustomEntropy:buffer?)->(),
AddEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_j)->(),
RemoveEntropyProvider:(ProviderFunction:EntropyProvider__DARKLUA_TYPE_j)->(),

Random:()->number,
RandomInt:(Min:number,Max:number?)->number,
RandomNumber:(Min:number,Max:number?)->number,
RandomBytes:(Count:number)->buffer,
RandomString:(Length:number,AsBuffer:boolean?)->string|buffer,
RandomHex:(Length:number)->string,
Ed25519ClampedBytes:(Input:buffer)->buffer,
Ed25519Random:()->buffer,
}local a={cache={}::any}do do local function __modImpl()



















local function FromByteAndSize(b:number,c:number)
local d=buffer.create(c)
buffer.fill(d,0,b)
return d
end

local function ToBigEndian(b:buffer)
for c=0,buffer.len(b)-1,4 do
buffer.writeu32(b,c,bit32.byteswap(buffer.readu32(b,c)))
end
end

local function ConcatenateBuffers(b:buffer,c:buffer)
local d=buffer.len(b)
local e=buffer.create(d+buffer.len(c))

buffer.copy(e,0,b)
buffer.copy(e,d,c)

return e
end

local function XORBuffer(b:buffer,c:buffer)
local d=math.min(buffer.len(b),buffer.len(c))
local e=buffer.create(d)

for f=0,d-1 do
local g=buffer.readu8(b,f)
local h=buffer.readu8(c,f)
buffer.writeu8(e,f,bit32.bxor(g,h))
end

return e
end

local function ComputeBlockSizedKey(b:buffer,c:HashFunction__DARKLUA_TYPE_a,d:number,e:boolean?):buffer
local f=buffer.len(b)
if f>d then local
g, h=c(b)
if e~=false then
ToBigEndian(h)
end

local i=buffer.create(d)
buffer.copy(i,0,h)
return i
elseif f<d then
local g=buffer.create(d)
buffer.copy(g,0,b)
return g
end

return b
end

local function HMAC(b:buffer,c:buffer,d:HashFunction__DARKLUA_TYPE_a,e:number,f:boolean?):(string,buffer)
local g=ComputeBlockSizedKey(c,d,e,f)
local h=XORBuffer(g,FromByteAndSize(0x5C,e))
local i=XORBuffer(g,FromByteAndSize(0x36,e))local
j, k=d(ConcatenateBuffers(i,b))

if f~=false then
ToBigEndian(k)
end

local l=ConcatenateBuffers(h,k)
return d(l)
end

return HMAC end function a.a():typeof(__modImpl())local b=a.cache.a if not b then b={c=__modImpl()}a.cache.a=b end return b.c end end do local function __modImpl()






























local b={}

local c=buffer.create(512)do
local d="0123456789abcdef"
for e=0,255 do
local f=bit32.rshift(e,4)
local g=e%16

local h=string.byte(d,f+1)
local i=string.byte(d,g+1)

local j=h+bit32.lshift(i,8)
buffer.writeu16(c,e*2,j)
end
end

local d,e=buffer.create(96),buffer.create(96)do
local f=0
local g=29
local function GetNextBit():number
local h=g%2
g=bit32.bxor((g-h)//2,142*h)

return h
end

for h=0,23 do
local i=0
local j:number

for k=1,6 do
j=if j then j*j*2 else 1
i+=GetNextBit()*j
end

local k=GetNextBit()*j
buffer.writeu32(e,h*4,k)
buffer.writeu32(d,h*4,i+k*f)
end
end

local f=buffer.create(100)
local g=buffer.create(100)
local h=buffer.fromstring"KMAC"

local function Keccak(i:buffer,j:buffer,k:buffer,l:number,m:number,n:number):()
local o=n//8
local p,q=e,d

for r=l,l+m-1,n do
for s=0,(o-1)*4,4 do
local t=r+s*2

buffer.writeu32(i,s,bit32.bxor(
buffer.readu32(i,s),
buffer.readu32(k,t)
))

buffer.writeu32(j,s,bit32.bxor(
buffer.readu32(j,s),
buffer.readu32(k,t+4)
))
end

local s,t=buffer.readu32(i,0),buffer.readu32(j,0)
local u,v=buffer.readu32(i,4),buffer.readu32(j,4)
local w,x=buffer.readu32(i,8),buffer.readu32(j,8)

local y,z=buffer.readu32(i,12),buffer.readu32(j,12)
local A,B=buffer.readu32(i,16),buffer.readu32(j,16)
local C,D=buffer.readu32(i,20),buffer.readu32(j,20)

local E,F=buffer.readu32(i,24),buffer.readu32(j,24)
local G,H=buffer.readu32(i,28),buffer.readu32(j,28)
local I,J=buffer.readu32(i,32),buffer.readu32(j,32)

local K,L=buffer.readu32(i,36),buffer.readu32(j,36)
local M,N=buffer.readu32(i,40),buffer.readu32(j,40)
local O,P=buffer.readu32(i,44),buffer.readu32(j,44)

local Q,R=buffer.readu32(i,48),buffer.readu32(j,48)
local S,T=buffer.readu32(i,52),buffer.readu32(j,52)
local U,V=buffer.readu32(i,56),buffer.readu32(j,56)

local W,X=buffer.readu32(i,60),buffer.readu32(j,60)
local Y,Z=buffer.readu32(i,64),buffer.readu32(j,64)
local _,aa=buffer.readu32(i,68),buffer.readu32(j,68)

local ab,ac=buffer.readu32(i,72),buffer.readu32(j,72)
local ad,ae=buffer.readu32(i,76),buffer.readu32(j,76)
local af,ag=buffer.readu32(i,80),buffer.readu32(j,80)

local ah,ai=buffer.readu32(i,84),buffer.readu32(j,84)
local aj,ak=buffer.readu32(i,88),buffer.readu32(j,88)
local al,am=buffer.readu32(i,92),buffer.readu32(j,92)

local an,ao=buffer.readu32(i,96),buffer.readu32(j,96)

for ap=0,92,4 do
local aq,ar=bit32.bxor(s,C,M,W,af),bit32.bxor(t,D,N,X,ag)
local as,at=bit32.bxor(u,E,O,Y,ah),bit32.bxor(v,F,P,Z,ai)
local au,av=bit32.bxor(w,G,Q,_,aj),bit32.bxor(x,H,R,aa,ak)
local aw,ax=bit32.bxor(y,I,S,ab,al),bit32.bxor(z,J,T,ac,am)
local ay,az=bit32.bxor(A,K,U,ad,an),bit32.bxor(B,L,V,ae,ao)

local aA,aB=bit32.bxor(aq,au*2+av//2147483648),bit32.bxor(ar,av*2+au//2147483648)
local aC,aD=bit32.bxor(aA,u),bit32.bxor(aB,v)
local aE,aF=bit32.bxor(aA,E),bit32.bxor(aB,F)
local aG,aH=bit32.bxor(aA,O),bit32.bxor(aB,P)
local aI,aJ=bit32.bxor(aA,Y),bit32.bxor(aB,Z)
local aK,aL=bit32.bxor(aA,ah),bit32.bxor(aB,ai)

u=aE//1048576+(aF*4096);v=aF//1048576+(aE*4096)
E=aI//524288+(aJ*8192);F=aJ//524288+(aI*8192)
O=aC*2+aD//2147483648;P=aD*2+aC//2147483648
Y=aG*1024+aH//4194304;Z=aH*1024+aG//4194304
ah=aK*4+aL//1073741824;ai=aL*4+aK//1073741824

aA=bit32.bxor(as,aw*2+ax//2147483648);aB=bit32.bxor(at,ax*2+aw//2147483648)
aC=bit32.bxor(aA,w);aD=bit32.bxor(aB,x)
aE=bit32.bxor(aA,G);aF=bit32.bxor(aB,H)
aG=bit32.bxor(aA,Q);aH=bit32.bxor(aB,R)
aI=bit32.bxor(aA,_);aJ=bit32.bxor(aB,aa)
aK=bit32.bxor(aA,aj);aL=bit32.bxor(aB,ak)

w=aG//2097152+(aH*2048);x=aH//2097152+(aG*2048)
G=aK//8+bit32.bor(aL*536870912,0);H=aL//8+bit32.bor(aK*536870912,0)
Q=aE*64+aF//67108864;R=aF*64+aE//67108864
_=(aI*32768)+aJ//131072;aa=(aJ*32768)+aI//131072
aj=aC//4+bit32.bor(aD*1073741824,0);ak=aD//4+bit32.bor(aC*1073741824,0)

aA=bit32.bxor(au,ay*2+az//2147483648);aB=bit32.bxor(av,az*2+ay//2147483648)
aC=bit32.bxor(aA,y);aD=bit32.bxor(aB,z)
aE=bit32.bxor(aA,I);aF=bit32.bxor(aB,J)
aG=bit32.bxor(aA,S);aH=bit32.bxor(aB,T)
aI=bit32.bxor(aA,ab);aJ=bit32.bxor(aB,ac)
aK=bit32.bxor(aA,al);aL=bit32.bxor(aB,am)

y=bit32.bor(aI*2097152,0)+aJ//2048;z=bit32.bor(aJ*2097152,0)+aI//2048
I=bit32.bor(aC*268435456,0)+aD//16;J=bit32.bor(aD*268435456,0)+aC//16
S=bit32.bor(aG*33554432,0)+aH//128;T=bit32.bor(aH*33554432,0)+aG//128
ab=aK//256+bit32.bor(aL*16777216,0);ac=aL//256+bit32.bor(aK*16777216,0)
al=aE//512+bit32.bor(aF*8388608,0);am=aF//512+bit32.bor(aE*8388608,0)
aA=bit32.bxor(aw,aq*2+ar//2147483648);aB=bit32.bxor(ax,ar*2+aq//2147483648)

aC=bit32.bxor(aA,A);aD=bit32.bxor(aB,B)
aE=bit32.bxor(aA,K);aF=bit32.bxor(aB,L)
aG=bit32.bxor(aA,U);aH=bit32.bxor(aB,V)
aI=bit32.bxor(aA,ad);aJ=bit32.bxor(aB,ae)
aK=bit32.bxor(aA,an);aL=bit32.bxor(aB,ao)

A=(aK*16384)+aL//262144;B=(aL*16384)+aK//262144
K=bit32.bor(aE*1048576,0)+aF//4096;L=bit32.bor(aF*1048576,0)+aE//4096
U=aI*256+aJ//16777216;V=aJ*256+aI//16777216
ad=bit32.bor(aC*134217728,0)+aD//32;ae=bit32.bor(aD*134217728,0)+aC//32
an=aG//33554432+aH*128;ao=aH//33554432+aG*128

aA=bit32.bxor(ay,as*2+at//2147483648);aB=bit32.bxor(az,at*2+as//2147483648)
aE=bit32.bxor(aA,C);aF=bit32.bxor(aB,D)
aG=bit32.bxor(aA,M);aH=bit32.bxor(aB,N)
aI=bit32.bxor(aA,W);aJ=bit32.bxor(aB,X)
aK=bit32.bxor(aA,af);aL=bit32.bxor(aB,ag)
C=aG*8+aH//536870912;D=aH*8+aG//536870912
M=(aK*262144)+aL//16384;N=(aL*262144)+aK//16384
W=aE//268435456+aF*16;X=aF//268435456+aE*16
af=aI//8388608+aJ*512;ag=aJ//8388608+aI*512
s=bit32.bxor(aA,s);t=bit32.bxor(aB,t)

s,u,w,y,A=bit32.bxor(s,bit32.band(-1-u,w)),bit32.bxor(u,bit32.band(-1-w,y)),bit32.bxor(w,bit32.band(-1-y,A)),bit32.bxor(y,bit32.band(-1-A,s)),bit32.bxor(A,bit32.band(-1-s,u))::number
t,v,x,z,B=bit32.bxor(t,bit32.band(-1-v,x)),bit32.bxor(v,bit32.band(-1-x,z)),bit32.bxor(x,bit32.band(-1-z,B)),bit32.bxor(z,bit32.band(-1-B,t)),bit32.bxor(B,bit32.band(-1-t,v))::number
C,E,G,I,K=bit32.bxor(I,bit32.band(-1-K,C)),bit32.bxor(K,bit32.band(-1-C,E)),bit32.bxor(C,bit32.band(-1-E,G)),bit32.bxor(E,bit32.band(-1-G,I)),bit32.bxor(G,bit32.band(-1-I,K))::number
D,F,H,J,L=bit32.bxor(J,bit32.band(-1-L,D)),bit32.bxor(L,bit32.band(-1-D,F)),bit32.bxor(D,bit32.band(-1-F,H)),bit32.bxor(F,bit32.band(-1-H,J)),bit32.bxor(H,bit32.band(-1-J,L))::number
M,O,Q,S,U=bit32.bxor(O,bit32.band(-1-Q,S)),bit32.bxor(Q,bit32.band(-1-S,U)),bit32.bxor(S,bit32.band(-1-U,M)),bit32.bxor(U,bit32.band(-1-M,O)),bit32.bxor(M,bit32.band(-1-O,Q))::number
N,P,R,T,V=bit32.bxor(P,bit32.band(-1-R,T)),bit32.bxor(R,bit32.band(-1-T,V)),bit32.bxor(T,bit32.band(-1-V,N)),bit32.bxor(V,bit32.band(-1-N,P)),bit32.bxor(N,bit32.band(-1-P,R))::number
W,Y,_,ab,ad=bit32.bxor(ad,bit32.band(-1-W,Y)),bit32.bxor(W,bit32.band(-1-Y,_)),bit32.bxor(Y,bit32.band(-1-_,ab)),bit32.bxor(_,bit32.band(-1-ab,ad)),bit32.bxor(ab,bit32.band(-1-ad,W))::number
X,Z,aa,ac,ae=bit32.bxor(ae,bit32.band(-1-X,Z)),bit32.bxor(X,bit32.band(-1-Z,aa)),bit32.bxor(Z,bit32.band(-1-aa,ac)),bit32.bxor(aa,bit32.band(-1-ac,ae)),bit32.bxor(ac,bit32.band(-1-ae,X))::number
af,ah,aj,al,an=bit32.bxor(aj,bit32.band(-1-al,an)),bit32.bxor(al,bit32.band(-1-an,af)),bit32.bxor(an,bit32.band(-1-af,ah)),bit32.bxor(af,bit32.band(-1-ah,aj)),bit32.bxor(ah,bit32.band(-1-aj,al))::number
ag,ai,ak,am,ao=bit32.bxor(ak,bit32.band(-1-am,ao)),bit32.bxor(am,bit32.band(-1-ao,ag)),bit32.bxor(ao,bit32.band(-1-ag,ai)),bit32.bxor(ag,bit32.band(-1-ai,ak)),bit32.bxor(ai,bit32.band(-1-ak,am))::number

s=bit32.bxor(s,buffer.readu32(q,ap))
t=bit32.bxor(t,buffer.readu32(p,ap))
end

buffer.writeu32(i,0,s);buffer.writeu32(j,0,t)
buffer.writeu32(i,4,u);buffer.writeu32(j,4,v)
buffer.writeu32(i,8,w);buffer.writeu32(j,8,x)
buffer.writeu32(i,12,y);buffer.writeu32(j,12,z)
buffer.writeu32(i,16,A);buffer.writeu32(j,16,B)
buffer.writeu32(i,20,C);buffer.writeu32(j,20,D)
buffer.writeu32(i,24,E);buffer.writeu32(j,24,F)
buffer.writeu32(i,28,G);buffer.writeu32(j,28,H)
buffer.writeu32(i,32,I);buffer.writeu32(j,32,J)
buffer.writeu32(i,36,K);buffer.writeu32(j,36,L)
buffer.writeu32(i,40,M);buffer.writeu32(j,40,N)
buffer.writeu32(i,44,O);buffer.writeu32(j,44,P)
buffer.writeu32(i,48,Q);buffer.writeu32(j,48,R)
buffer.writeu32(i,52,S);buffer.writeu32(j,52,T)
buffer.writeu32(i,56,U);buffer.writeu32(j,56,V)
buffer.writeu32(i,60,W);buffer.writeu32(j,60,X)
buffer.writeu32(i,64,Y);buffer.writeu32(j,64,Z)
buffer.writeu32(i,68,_);buffer.writeu32(j,68,aa)
buffer.writeu32(i,72,ab);buffer.writeu32(j,72,ac)
buffer.writeu32(i,76,ad);buffer.writeu32(j,76,ae)
buffer.writeu32(i,80,af);buffer.writeu32(j,80,ag)
buffer.writeu32(i,84,ah);buffer.writeu32(j,84,ai)
buffer.writeu32(i,88,aj);buffer.writeu32(j,88,ak)
buffer.writeu32(i,92,al);buffer.writeu32(j,92,am)
buffer.writeu32(i,96,an);buffer.writeu32(j,96,ao)
end
end

local aa=buffer.create(5)
local ab=buffer.create(5)

local function LeftEncode(ac:number):(buffer,number)
local ad=aa

if ac<=0xFF then
buffer.writeu8(ad,0,1)
buffer.writeu8(ad,1,ac)
return ad,2
end

if ac<=0xFFFF then
buffer.writeu8(ad,0,2)
buffer.writeu16(ad,1,bit32.byteswap(bit32.lshift(ac,16)))
return ad,3
end

local ae=if ac>0xFFFFFF then 4 else 3
buffer.writeu8(ad,0,ae)
buffer.writeu32(ad,1,bit32.byteswap(bit32.lshift(ac,(4-ae)*8)))
return ad,ae+1
end

local function RightEncode(ac:number):(buffer,number)
local ad=ab

if ac<=0xFF then
buffer.writeu8(ad,0,ac)
buffer.writeu8(ad,1,1)
return ad,2
end

if ac<=0xFFFF then
buffer.writeu16(ad,0,bit32.byteswap(bit32.lshift(ac,16)))
buffer.writeu8(ad,2,2)
return ad,3
end

local ae=if ac>0xFFFFFF then 4 else 3
buffer.writeu32(ad,0,bit32.byteswap(bit32.lshift(ac,(4-ae)*8)))
buffer.writeu8(ad,ae,ae)
return ad,ae+1
end

local function EncodeString(ac:buffer):buffer
local ad=buffer.len(ac)

local ae,af=LeftEncode(ad*8)

local ag=buffer.create(af+ad)

buffer.copy(ag,0,ae,0,af)
buffer.copy(ag,af,ac,0,ad)

return ag
end

local function Bytepad(ac:buffer,ad:number):buffer
local ae=buffer.len(ac)

local af,ag=LeftEncode(ad)

local ah=ag+ae
local ai=ad-(ah%ad)
if ai==ad then
ai=0
end

local aj=buffer.create(ah+ai)
buffer.copy(aj,0,af,0,ag)
buffer.copy(aj,ag,ac,0,ae)

return aj
end

local function CSHAKE(ac:buffer,ad:buffer?,ae:buffer,af:number):()
buffer.fill(f,0,0,100)
buffer.fill(g,0,0,100)

local ag=f
local ah=g

local ai=buffer.len(ac)

local aj=EncodeString(h)
local ak=buffer.len(aj)

local al:buffer
if ad then
local am=EncodeString(ad)
local an=buffer.len(am)
al=buffer.create(ak+an)
buffer.copy(al,0,aj,0,ak)
buffer.copy(al,ak,am,0,an)
else
al=aj
end

local am=Bytepad(al,af)
local an=buffer.len(am)
local ao=buffer.len(ae)
local ap=an+ao

local aq=ap+1
local ar=aq%af
if ar~=0 then
aq+=(af-ar)
end

local as=buffer.create(aq)
buffer.copy(as,0,am,0,an)
buffer.copy(as,an,ae,0,ao)

local at=0x04
if aq-ap==1 then
buffer.writeu8(as,ap,bit32.bor(at,0x80))
else
buffer.writeu8(as,ap,at)
if aq-ap>2 then
buffer.fill(as,ap+1,0,aq-ap-2)
end
buffer.writeu8(as,aq-1,0x80)
end

Keccak(ag,ah,as,0,aq,af)

local au=0
local av=buffer.create(af)

while au<ai do
local aw=math.min(af,ai-au)

for ax=0,aw-1 do
local ay=au+ax
if ay<ai then
local az=ax//8
local aA=ax%8
local aB=az*4

local aC
if aA<4 then
aC=bit32.extract(buffer.readu32(ag,aB),aA*8,8)
else
aC=bit32.extract(buffer.readu32(ah,aB),(aA-4)*8,8)
end
buffer.writeu8(ac,ay,aC)
end
end

au+=aw

if au<ai then
Keccak(ag,ah,av,0,af,af)
end
end
end

function b.KMAC128(ac:buffer,ad:buffer,ae:buffer,af:buffer?):(string,buffer)
local ag=buffer.len(ae)

local ah=EncodeString(ad)
local ai=Bytepad(ah,168)

local aj=buffer.len(ai)
local ak=buffer.len(ac)

local al,am=RightEncode(ag*8)

local an=buffer.create(ag*2)
local ao=c

local ap=ag%8
local aq=0

local ar=buffer.create(aj+ak+am)
buffer.copy(ar,0,ai,0,aj)
buffer.copy(ar,aj,ac,0,ak)
buffer.copy(ar,aj+ak,al,0,am)

CSHAKE(ae,af,ar,168)

for as=0,ag-ap-1,8 do
local at=buffer.readu16(ao,buffer.readu8(ae,as)*2)
local au=buffer.readu16(ao,buffer.readu8(ae,as+1)*2)
local av=buffer.readu16(ao,buffer.readu8(ae,as+2)*2)
local aw=buffer.readu16(ao,buffer.readu8(ae,as+3)*2)
local ax=buffer.readu16(ao,buffer.readu8(ae,as+4)*2)
local ay=buffer.readu16(ao,buffer.readu8(ae,as+5)*2)
local az=buffer.readu16(ao,buffer.readu8(ae,as+6)*2)
local aA=buffer.readu16(ao,buffer.readu8(ae,as+7)*2)

buffer.writeu16(an,aq,at)
buffer.writeu16(an,aq+2,au)
buffer.writeu16(an,aq+4,av)
buffer.writeu16(an,aq+6,aw)
buffer.writeu16(an,aq+8,ax)
buffer.writeu16(an,aq+10,ay)
buffer.writeu16(an,aq+12,az)
buffer.writeu16(an,aq+14,aA)

aq+=16
end

for as=ag-ap,ag-1 do
local at=buffer.readu16(ao,buffer.readu8(ae,as)*2)
buffer.writeu16(an,aq,at)
aq+=2
end

return buffer.tostring(an),ae
end

function b.KMAC256(ac:buffer,ad:buffer,ae:buffer,af:buffer?):(string,buffer)
local ag=buffer.len(ae)

local ah=EncodeString(ad)
local ai=Bytepad(ah,136)

local aj=buffer.len(ai)
local ak=buffer.len(ac)

local al,am=RightEncode(ag*8)

local an=buffer.create(ag*2)
local ao=c

local ap=ag%8
local aq=0

local ar=buffer.create(aj+ak+am)
buffer.copy(ar,0,ai,0,aj)
buffer.copy(ar,aj,ac,0,ak)
buffer.copy(ar,aj+ak,al,0,am)

CSHAKE(ae,af,ar,136)

for as=0,ag-ap-1,8 do
local at=buffer.readu16(ao,buffer.readu8(ae,as)*2)
local au=buffer.readu16(ao,buffer.readu8(ae,as+1)*2)
local av=buffer.readu16(ao,buffer.readu8(ae,as+2)*2)
local aw=buffer.readu16(ao,buffer.readu8(ae,as+3)*2)
local ax=buffer.readu16(ao,buffer.readu8(ae,as+4)*2)
local ay=buffer.readu16(ao,buffer.readu8(ae,as+5)*2)
local az=buffer.readu16(ao,buffer.readu8(ae,as+6)*2)
local aA=buffer.readu16(ao,buffer.readu8(ae,as+7)*2)

buffer.writeu16(an,aq,at)
buffer.writeu16(an,aq+2,au)
buffer.writeu16(an,aq+4,av)
buffer.writeu16(an,aq+6,aw)
buffer.writeu16(an,aq+8,ax)
buffer.writeu16(an,aq+10,ay)
buffer.writeu16(an,aq+12,az)
buffer.writeu16(an,aq+14,aA)

aq+=16
end

for as=ag-ap,ag-1 do
local at=buffer.readu16(ao,buffer.readu8(ae,as)*2)
buffer.writeu16(an,aq,at)
aq+=2
end

return buffer.tostring(an),ae
end

return b end function a.b():typeof(__modImpl())local aa=a.cache.b if not aa then aa={c=__modImpl()}a.cache.b=aa end return aa.c end end do local function __modImpl()
















local aa=table.create(64)::{number}
local ab={
0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
}

local ac={
7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
}

local function PreProcess(ad:buffer):(buffer,number)
local ae=buffer.len(ad)
local af=ae*8

local ag=(56-((ae+1)%64))%64

local ah=ae+1+ag+8
local ai=buffer.create(ah)

buffer.copy(ai,0,ad)

buffer.writeu8(ai,ae,0x80)

local aj=ae+1+ag
for ak=0,7 do
local al=af%256
buffer.writeu8(ai,aj+ak,al)
af=bit32.rshift(af,8)
end

return ai,ah
end

local function DigestBlocks(ad:buffer,ae:number):(number,number,number,number)
local af,ag,ah,ai=0x67452301,0xefcdab89,0x98badcfe,0x10325476

local aj=aa
local ak=ab
local al=ac

for am=0,ae-1,64 do
for an=0,15 do
local ao=am+an*4
local ap=buffer.readu32(ad,ao)
aj[an+1]=ap
end

local an,ao,ap,aq=af,ag,ah,ai
local ar,as=0,0
for at=0,15 do
local au=aj[at+1]
as=bit32.bxor(aq,bit32.band(ao,bit32.bxor(ap,aq)))
ar=aq
aq=ap
ap=ao

ao=ao+bit32.lrotate(an+as+ak[at+1]+au,al[at+1])
an=ar
end

for at=16,31 do
local au=aj[(5*at+1)%16+1]
as=bit32.bxor(ap,bit32.band(aq,bit32.bxor(ao,ap)))
ar=aq
aq=ap
ap=ao
ao=ao+bit32.lrotate(an+as+ak[at+1]+au,al[at+1])
an=ar
end

for at=32,47 do
local au=aj[(3*at+5)%16+1]
as=bit32.bxor(ao,ap,aq)
ar=aq
aq=ap
ap=ao
ao=ao+bit32.lrotate(an+as+ak[at+1]+au,al[at+1])
an=ar
end

for at=48,63 do
local au=aj[(7*at)%16+1]
as=bit32.bxor(ap,bit32.bor(ao,bit32.bnot(aq)))
ar=aq
aq=ap
ap=ao
ao=ao+bit32.lrotate(an+as+ak[at+1]+au,al[at+1])
an=ar
end

af=bit32.bor(an+af,0)
ag=bit32.bor(ao+ag,0)
ah=bit32.bor(ap+ah,0)
ai=bit32.bor(aq+ai,0)
end

return bit32.byteswap(af),bit32.byteswap(ag),bit32.byteswap(ah),bit32.byteswap(ai)
end

local function MD5(ad:buffer,ae:buffer?):(string,buffer)
if ae and buffer.len(ae)>0 then
local af=buffer.create(buffer.len(ad)+buffer.len(ae))
buffer.copy(af,0,ad)
buffer.copy(af,buffer.len(ad),ae)
ad=af
end

local af,ag=PreProcess(ad)

local ah,ai,aj,ak=DigestBlocks(af,ag)
local al=buffer.create(16)

buffer.writeu32(al,0,ah)
buffer.writeu32(al,4,ai)
buffer.writeu32(al,8,aj)
buffer.writeu32(al,12,ak)

return string.format("%08x%08x%08x%08x",ah,ai,aj,ak),al
end

return MD5 end function a.c():typeof(__modImpl())local aa=a.cache.c if not aa then aa={c=__modImpl()}a.cache.c=aa end return aa.c end end do local function __modImpl()


























local aa=buffer.create(320)

local function PreProcess(ab:buffer):(buffer,number)
local ac=buffer.len(ab)
local ad=(64-((ac+9)%64))%64

local ae=ac+1+ad+8
local af=buffer.create(ae)
buffer.copy(af,0,ab)
buffer.writeu8(af,ac,128)

local ag=ac*8
for ah=7,0,-1 do
local ai=ag%256
buffer.writeu8(af,ah+ac+1+ad,ai)
ag=(ag-ai)/256
end

return af,ae
end

local function DigestBlocks(ab:buffer,ac:number):(number,number,number,number,number)
local ad,ae,af,ag,ah=0x67452301,0xefcdaB89,0x98badcfe,0x10325476,0xc3d2e1f0
local ai=aa

for aj=0,ac-1,64 do
for ak=0,60,4 do
buffer.writeu32(ai,ak,bit32.byteswap(buffer.readu32(ab,aj+ak)))
end

for ak=64,316,4 do
buffer.writeu32(ai,ak,bit32.lrotate(bit32.bxor(
buffer.readu32(ai,ak-12),
buffer.readu32(ai,ak-32),
buffer.readu32(ai,ak-56),
buffer.readu32(ai,ak-64)
),1))
end

local ak,al,am,an,ao=ad,ae,af,ag,ah

local ap
for aq=0,19 do
ap=bit32.lrotate(ak,5)+
bit32.band(al,am)+bit32.band(-1-al,an)+
ao+0x5a827999+
buffer.readu32(ai,aq*4)

ao,an,am,al,ak=an,am,bit32.lrotate(al,30),ak,ap
end

for aq=20,39 do
ap=bit32.lrotate(ak,5)+
bit32.bxor(al,am,an)+
ao+0x6ed9eba1+
buffer.readu32(ai,aq*4)

ao,an,am,al,ak=an,am,bit32.lrotate(al,30),ak,ap
end

for aq=40,59 do
ap=bit32.lrotate(ak,5)+
bit32.band(an,am)+bit32.band(al,bit32.bxor(an,am))+
ao+0x8f1bbcdc+
buffer.readu32(ai,aq*4)

ao,an,am,al,ak=an,am,bit32.lrotate(al,30),ak,ap
end

for aq=60,79 do
ap=bit32.lrotate(ak,5)+
bit32.bxor(al,am,an)+
ao+0xca62c1d6+
buffer.readu32(ai,aq*4)

ao,an,am,al,ak=an,am,bit32.lrotate(al,30),ak,ap
end

ad=bit32.bor(ad+ak,0)
ae=bit32.bor(ae+al,0)
af=bit32.bor(af+am,0)
ag=bit32.bor(ag+an,0)
ah=bit32.bor(ah+ao,0)
end

return ad,ae,af,ag,ah
end

local function SHA1(ab:buffer,ac:buffer?):string
if ac and buffer.len(ac)>0 then
local ad=buffer.create(buffer.len(ab)+buffer.len(ac))

buffer.copy(ad,0,ab)
buffer.copy(ad,buffer.len(ab),ac)

ab=ad
end

local ad,ae=PreProcess(ab)
return string.format("%08x%08x%08x%08x%08x",DigestBlocks(ad,ae))
end

return SHA1 end function a.d():typeof(__modImpl())local aa=a.cache.d if not aa then aa={c=__modImpl()}a.cache.d=aa end return aa.c end end do local function __modImpl()
















local aa=buffer.create(256)do
local ab={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}

for ac,ad in ipairs(ab)do
local ae=(ac-1)*4
buffer.writeu32(aa,ae,ad)
end
end

local function PreProcess(ab:buffer):(buffer,number)
local ac=buffer.len(ab)
local ad=-(ac+9)%64

local ae=ac+1+ad+8
local af=buffer.create(ae)
buffer.copy(af,0,ab)
buffer.writeu8(af,ac,128)
local ag=ac*8
for ah=7,0,-1 do
local ai=ag%256
buffer.writeu8(af,ah+ac+1+ad,ai)
ag=(ag-ai)/256
end

return af,ae
end

local ab=buffer.create(256)
local function DigestBlocks(ac:buffer,ad:number):(number,number,number,number,number,number,number)
local ae,af,ag,ah=0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939
local ai,aj,ak,al=0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4

local am=ab
local an=aa

for ao=0,ad-1,64 do
for ap=0,60,4 do
buffer.writeu32(am,ap,bit32.byteswap(buffer.readu32(ac,ao+ap)))
end

for ap=64,252,4 do
local aq=buffer.readu32(am,ap-60)
local ar=bit32.bxor(bit32.rrotate(aq,7),bit32.rrotate(aq,18),bit32.rshift(aq,3))

local as=buffer.readu32(am,ap-8)
local at=bit32.bxor(bit32.rrotate(as,17),bit32.rrotate(as,19),bit32.rshift(as,10))

local au,av=buffer.readu32(am,ap-28),buffer.readu32(am,ap-64)
buffer.writeu32(am,ap,(av+ar+au+at))
end

local ap,aq,ar,as,at,au,av,aw=ae,af,ag,ah,ai,aj,ak,al

for ax=0,252,4 do
local ay=bit32.bxor(bit32.rrotate(ai,6),bit32.rrotate(ai,11),bit32.rrotate(ai,25))
local az=bit32.bxor(bit32.band(ai,aj),bit32.band(bit32.bnot(ai),ak))
local aA=al+ay+az+buffer.readu32(an,ax)+buffer.readu32(am,ax)
al,ak,aj,ai,ah=ak,aj,ai,ah+aA,ag

local aB=bit32.bxor(bit32.rrotate(ae,2),bit32.rrotate(ae,13),bit32.rrotate(ae,22))
local aC=bit32.bxor(bit32.band(ae,af),bit32.band(ae,ag),bit32.band(af,ag))
ag,af,ae=af,ae,aA+aB+aC
end

ae,af,ag,ah,ai,aj,ak,al=
bit32.bor(ae+ap,0),
bit32.bor(af+aq,0),
bit32.bor(ag+ar,0),
bit32.bor(ah+as,0),
bit32.bor(ai+at,0),
bit32.bor(aj+au,0),
bit32.bor(ak+av,0),
bit32.bor(al+aw,0)
end

return ae,af,ag,ah,ai,aj,ak
end

local function SHA224(ac:buffer):(string,buffer)
local ad,ae=PreProcess(ac)
local af,ag,ah,ai,aj,ak,al=DigestBlocks(ad,ae)

local am=buffer.create(28)

buffer.writeu32(am,0,af)
buffer.writeu32(am,4,ag)
buffer.writeu32(am,8,ah)
buffer.writeu32(am,12,ai)
buffer.writeu32(am,16,aj)
buffer.writeu32(am,20,ak)
buffer.writeu32(am,24,al)

return string.format("%08x%08x%08x%08x%08x%08x%08x",af,ag,ah,ai,aj,ak,al),am
end

return SHA224 end function a.e():typeof(__modImpl())local aa=a.cache.e if not aa then aa={c=__modImpl()}a.cache.e=aa end return aa.c end end do local function __modImpl()















local aa=buffer.create(256)do
local ab={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}

for ac,ad in ipairs(ab)do
local ae=(ac-1)*4
buffer.writeu32(aa,ae,ad)
end
end

local function PreProcess(ab:buffer):(buffer,number)
local ac=buffer.len(ab)
local ad=-(ac+9)%64

local ae=ac+1+ad+8
local af=buffer.create(ae)
buffer.copy(af,0,ab)
buffer.writeu8(af,ac,128)
local ag=ac*8
for ah=7,0,-1 do
local ai=ag%256
buffer.writeu8(af,ah+ac+1+ad,ai)
ag=(ag-ai)/256
end

return af,ae
end

local ab=buffer.create(256)
local function DigestBlocks(ac:buffer,ad:number):(number,number,number,number,number,number,number,number)
local ae,af,ag,ah=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
local ai,aj,ak,al=0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

local am=ab
local an=aa

for ao=0,ad-1,64 do
for ap=0,60,4 do
buffer.writeu32(am,ap,bit32.byteswap(buffer.readu32(ac,ao+ap)))
end

for ap=64,252,4 do
local aq=buffer.readu32(am,ap-60)
local ar=bit32.bxor(bit32.rrotate(aq,7),bit32.rrotate(aq,18),bit32.rshift(aq,3))

local as=buffer.readu32(am,ap-8)
local at=bit32.bxor(bit32.rrotate(as,17),bit32.rrotate(as,19),bit32.rshift(as,10))

local au,av=buffer.readu32(am,ap-28),buffer.readu32(am,ap-64)
buffer.writeu32(am,ap,(av+ar+au+at))
end

local ap,aq,ar,as,at,au,av,aw=ae,af,ag,ah,ai,aj,ak,al

for ax=0,252,4 do
local ay=bit32.bxor(bit32.rrotate(ai,6),bit32.rrotate(ai,11),bit32.rrotate(ai,25))
local az=bit32.bxor(bit32.band(ai,aj),bit32.band(bit32.bnot(ai),ak))
local aA=al+ay+az+buffer.readu32(an,ax)+buffer.readu32(am,ax)
al,ak,aj,ai,ah=ak,aj,ai,ah+aA,ag

local aB=bit32.bxor(bit32.rrotate(ae,2),bit32.rrotate(ae,13),bit32.rrotate(ae,22))
local aC=bit32.bxor(bit32.band(ae,af),bit32.band(ae,ag),bit32.band(af,ag))
ag,af,ae=af,ae,aA+aB+aC
end

ae,af,ag,ah,ai,aj,ak,al=
bit32.bor(ae+ap,0),
bit32.bor(af+aq,0),
bit32.bor(ag+ar,0),
bit32.bor(ah+as,0),
bit32.bor(ai+at,0),
bit32.bor(aj+au,0),
bit32.bor(ak+av,0),
bit32.bor(al+aw,0)::number
end

return ae,af,ag,ah,ai,aj,ak,al
end

local function SHA256(ac:buffer):(string,buffer)
local ad,ae=PreProcess(ac)
local af,ag,ah,ai,aj,ak,al,am=DigestBlocks(ad,ae)

local an=buffer.create(32)

buffer.writeu32(an,0,af)
buffer.writeu32(an,4,ag)
buffer.writeu32(an,8,ah)
buffer.writeu32(an,12,ai)
buffer.writeu32(an,16,aj)
buffer.writeu32(an,20,ak)
buffer.writeu32(an,24,al)
buffer.writeu32(an,28,am)

return string.format("%08x%08x%08x%08x%08x%08x%08x%08x",af,ag,ah,ai,aj,ak,al,am),an
end

return SHA256 end function a.f():typeof(__modImpl())local aa=a.cache.f if not aa then aa={c=__modImpl()}a.cache.f=aa end return aa.c end end do local function __modImpl()
















local aa={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
0xca273ece,0xd186b8c7,0xeada7dd6,0xf57d4f7f,0x06f067aa,0x0a637dc5,0x113f9804,0x1b710b35,
0x28db77f5,0x32caab7b,0x3c9ebe0a,0x431d67c4,0x4cc5d4be,0x597f299c,0x5fcb6fab,0x6c44198c,
}

local ab={
0xd728ae22,0x23ef65cd,0xec4d3b2f,0x8189dbbc,0xf348b538,0xb605d019,0xaf194f9b,0xda6d8118,
0xa3030242,0x45706fbe,0x4ee4b28c,0xd5ffb4e2,0xf27b896f,0x3b1696b1,0x25c71235,0xcf692694,
0x9ef14ad2,0x384f25e3,0x8b8cd5b5,0x77ac9c65,0x592b0275,0x6ea6e483,0xbd41fbd4,0x831153b5,
0xee66dfab,0x2db43210,0x98fb213f,0xbeef0ee4,0x3da88fc2,0x930aa725,0xe003826f,0x0a0e6e70,
0x46d22ffc,0x5c26c926,0x5ac42aed,0x9d95b3df,0x8baf63de,0x3c77b2a8,0x47edaee6,0x1482353b,
0x4cf10364,0xbc423001,0xd0f89791,0x0654be30,0xd6ef5218,0x5565a910,0x5771202a,0x32bbd1b8,
0xb8d2d0c8,0x5141ab53,0xdf8eeb99,0xe19b48a8,0xc5c95a63,0xe3418acb,0x7763e373,0xd6b2b8a3,
0x5defb2fc,0x43172f60,0xa1f0ab72,0x1a6439ec,0x23631e28,0xde82bde9,0xb2c67915,0xe372532b,
0xea26619c,0x21c0c207,0xcde0eb1e,0xee6ed178,0x72176fba,0xa2c898a6,0xbef90dae,0x131c471b,
0x23047d84,0x40c72493,0x15c9bebc,0x9c100d4c,0xcb3e42b6,0xfc657e2a,0x3ad6faec,0x4a475817,
}

local ac=table.create(80)::{number}
local ad=table.create(80)::{number}
local ae=buffer.create(48)

local function PreProcess(af:buffer):(buffer,number)
local ag=buffer.len(af)
local ah=(128-((ag+17)%128))%128
local ai=ag+1+ah+16

local aj=buffer.create(ai)
buffer.copy(aj,0,af)
buffer.writeu8(aj,ag,0x80)
buffer.fill(aj,ag+1,0,ah+8)

local ak=ag*8
local al=ag+1+ah+8

for am=7,0,-1 do
buffer.writeu8(aj,al+am,ak%256)
ak=ak//256
end

return aj,ai
end

local function DigestBlocks(af:buffer,ag:number)
local ah,ai=ac,ad
local aj,ak=aa,ab

local al,am,an,ao=0xcbbb9d5d,0x629a292a,0x9159015a,0x152fecd8
local ap,aq,ar,as=0x67332667,0x8eb44a87,0xdb0c2e0d,0x47b5481d
local at,au,av,aw=0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939
local ax,ay,az,aA=0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4

for aB=0,ag-1,128 do
for aC=1,16 do
local aD=aB+(aC-1)*8
ah[aC]=bit32.byteswap(buffer.readu32(af,aD))
ai[aC]=bit32.byteswap(buffer.readu32(af,aD+4))
end

for aC=17,80 do
local aD,aE=ah[aC-15],ai[aC-15]
local aF,aG=ah[aC-2],ai[aC-2]

local aH=bit32.bxor(bit32.rshift(aE,1)+bit32.lshift(aD,31),bit32.rshift(aE,8)+bit32.lshift(aD,24),bit32.rshift(aE,7)+bit32.lshift(aD,25))
local aI=bit32.bxor(bit32.rshift(aG,19)+bit32.lshift(aF,13),bit32.lshift(aG,3)+bit32.rshift(aF,29),bit32.rshift(aG,6)+bit32.lshift(aF,26))

local aJ=ai[aC-16]+aH+ai[aC-7]+aI
ai[aC]=bit32.bor(aJ,0)
ah[aC]=bit32.bxor(bit32.rshift(aD,1)+bit32.lshift(aE,31),bit32.rshift(aD,8)+bit32.lshift(aE,24),bit32.rshift(aD,7))+
bit32.bxor(bit32.rshift(aF,19)+bit32.lshift(aG,13),bit32.lshift(aF,3)+bit32.rshift(aG,29),bit32.rshift(aF,6))+
ah[aC-16]+ah[aC-7]+aJ//0x100000000
end

local aC,aD=al,at
local aE,aF=am,au
local aG,aH=an,av
local aI,aJ=ao,aw
local aK,aL=ap,ax
local b,c=aq,ay
local d,e=ar,az
local f,g=as,aA

for h=1,79,2 do
local i=bit32.bxor(bit32.rshift(aL,14)+bit32.lshift(aK,18),bit32.rshift(aL,18)+bit32.lshift(aK,14),bit32.lshift(aL,23)+bit32.rshift(aK,9))
local j=bit32.bxor(bit32.rshift(aK,14)+bit32.lshift(aL,18),bit32.rshift(aK,18)+bit32.lshift(aL,14),bit32.lshift(aK,23)+bit32.rshift(aL,9))
local k=bit32.bxor(bit32.rshift(aD,28)+bit32.lshift(aC,4),bit32.lshift(aD,30)+bit32.rshift(aC,2),bit32.lshift(aD,25)+bit32.rshift(aC,7))
local l=bit32.bxor(bit32.rshift(aC,28)+bit32.lshift(aD,4),bit32.lshift(aC,30)+bit32.rshift(aD,2),bit32.lshift(aC,25)+bit32.rshift(aD,7))
local m=bit32.band(aL,c)+bit32.band(-1-aL,e)
local n=bit32.band(aK,b)+bit32.band(-1-aK,d)
local o=bit32.band(aH,aF)+bit32.band(aD,bit32.bxor(aH,aF))
local p=bit32.band(aG,aE)+bit32.band(aC,bit32.bxor(aG,aE))

local q=g+i+m+ak[h]+ai[h]
local r=f+j+n+aj[h]+ah[h]+q//0x100000000
q=bit32.bor(q,0)

f,g=d,e
d,e=b,c
b,c=aK,aL

local s=aJ+q
aK=aI+r+s//0x100000000
aL=bit32.bor(s,0)

aI,aJ=aG,aH
aG,aH=aE,aF
aE,aF=aC,aD

local t=q+k+o
aC=r+l+p+t//0x100000000
aD=bit32.bor(t,0)

local u=h+1
i=bit32.bxor(bit32.rshift(aL,14)+bit32.lshift(aK,18),bit32.rshift(aL,18)+bit32.lshift(aK,14),bit32.lshift(aL,23)+bit32.rshift(aK,9))
j=bit32.bxor(bit32.rshift(aK,14)+bit32.lshift(aL,18),bit32.rshift(aK,18)+bit32.lshift(aL,14),bit32.lshift(aK,23)+bit32.rshift(aL,9))
k=bit32.bxor(bit32.rshift(aD,28)+bit32.lshift(aC,4),bit32.lshift(aD,30)+bit32.rshift(aC,2),bit32.lshift(aD,25)+bit32.rshift(aC,7))
l=bit32.bxor(bit32.rshift(aC,28)+bit32.lshift(aD,4),bit32.lshift(aC,30)+bit32.rshift(aD,2),bit32.lshift(aC,25)+bit32.rshift(aD,7))
m=bit32.band(aL,c)+bit32.band(-1-aL,e)
n=bit32.band(aK,b)+bit32.band(-1-aK,d)
o=bit32.band(aH,aF)+bit32.band(aD,bit32.bxor(aH,aF))
p=bit32.band(aG,aE)+bit32.band(aC,bit32.bxor(aG,aE))

q=g+i+m+ak[u]+ai[u]
r=f+j+n+aj[u]+ah[u]+q//0x100000000
q=bit32.bor(q,0)

f,g=d,e
d,e=b,c
b,c=aK,aL

s=aJ+q
aK=aI+r+s//0x100000000
aL=bit32.bor(s,0)

aI,aJ=aG,aH
aG,aH=aE,aF
aE,aF=aC,aD

t=q+k+o
aC=r+l+p+t//0x100000000
aD=bit32.bor(t,0)
end

at=at+aD
al=bit32.bor(al+aC+at//0x100000000,0)
at=bit32.bor(at,0)

au=au+aF
am=bit32.bor(am+aE+au//0x100000000,0)
au=bit32.bor(au,0)

av=av+aH
an=bit32.bor(an+aG+av//0x100000000,0)
av=bit32.bor(av,0)

aw=aw+aJ
ao=bit32.bor(ao+aI+aw//0x100000000,0)
aw=bit32.bor(aw,0)

ax=ax+aL
ap=bit32.bor(ap+aK+ax//0x100000000,0)
ax=bit32.bor(ax,0)

ay=ay+c
aq=bit32.bor(aq+b+ay//0x100000000,0)
ay=bit32.bor(ay,0)

az=az+e
ar=bit32.bor(ar+d+az//0x100000000,0)
az=bit32.bor(az,0)

aA=aA+g
as=bit32.bor(as+f+aA//0x100000000,0)
aA=bit32.bor(aA,0)
end

buffer.writeu32(ae,0,al)
buffer.writeu32(ae,4,at)
buffer.writeu32(ae,8,am)
buffer.writeu32(ae,12,au)
buffer.writeu32(ae,16,an)
buffer.writeu32(ae,20,av)
buffer.writeu32(ae,24,ao)
buffer.writeu32(ae,28,aw)
buffer.writeu32(ae,32,ap)
buffer.writeu32(ae,36,ax)
buffer.writeu32(ae,40,aq)
buffer.writeu32(ae,44,ay)
end

local function SHA384(af:buffer):(string,buffer)
local ag,ah=PreProcess(af)
DigestBlocks(ag,ah)

local ai,aj=buffer.readu32(ae,0),buffer.readu32(ae,4)
local ak,al=buffer.readu32(ae,8),buffer.readu32(ae,12)
local am,an=buffer.readu32(ae,16),buffer.readu32(ae,20)
local ao,ap=buffer.readu32(ae,24),buffer.readu32(ae,28)
local aq,ar=buffer.readu32(ae,32),buffer.readu32(ae,36)
local as,at=buffer.readu32(ae,40),buffer.readu32(ae,44)

return string.format(
"%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
ai,aj,ak,al,am,an,ao,ap,aq,ar,as,at
),ae
end

return SHA384 end function a.g():typeof(__modImpl())local aa=a.cache.g if not aa then aa={c=__modImpl()}a.cache.g=aa end return aa.c end end do local function __modImpl()
















local aa={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
0xca273ece,0xd186b8c7,0xeada7dd6,0xf57d4f7f,0x06f067aa,0x0a637dc5,0x113f9804,0x1b710b35,
0x28db77f5,0x32caab7b,0x3c9ebe0a,0x431d67c4,0x4cc5d4be,0x597f299c,0x5fcb6fab,0x6c44198c,
}

local ab={
0xd728ae22,0x23ef65cd,0xec4d3b2f,0x8189dbbc,0xf348b538,0xb605d019,0xaf194f9b,0xda6d8118,
0xa3030242,0x45706fbe,0x4ee4b28c,0xd5ffb4e2,0xf27b896f,0x3b1696b1,0x25c71235,0xcf692694,
0x9ef14ad2,0x384f25e3,0x8b8cd5b5,0x77ac9c65,0x592b0275,0x6ea6e483,0xbd41fbd4,0x831153b5,
0xee66dfab,0x2db43210,0x98fb213f,0xbeef0ee4,0x3da88fc2,0x930aa725,0xe003826f,0x0a0e6e70,
0x46d22ffc,0x5c26c926,0x5ac42aed,0x9d95b3df,0x8baf63de,0x3c77b2a8,0x47edaee6,0x1482353b,
0x4cf10364,0xbc423001,0xd0f89791,0x0654be30,0xd6ef5218,0x5565a910,0x5771202a,0x32bbd1b8,
0xb8d2d0c8,0x5141ab53,0xdf8eeb99,0xe19b48a8,0xc5c95a63,0xe3418acb,0x7763e373,0xd6b2b8a3,
0x5defb2fc,0x43172f60,0xa1f0ab72,0x1a6439ec,0x23631e28,0xde82bde9,0xb2c67915,0xe372532b,
0xea26619c,0x21c0c207,0xcde0eb1e,0xee6ed178,0x72176fba,0xa2c898a6,0xbef90dae,0x131c471b,
0x23047d84,0x40c72493,0x15c9bebc,0x9c100d4c,0xcb3e42b6,0xfc657e2a,0x3ad6faec,0x4a475817,
}

local ac=table.create(80)::{number}
local ad=table.create(80)::{number}
local ae=buffer.create(64)

local function PreProcess(af:buffer):(buffer,number)
local ag=buffer.len(af)
local ah=(128-((ag+17)%128))%128
local ai=ag+1+ah+16

local aj=buffer.create(ai)
buffer.copy(aj,0,af)
buffer.writeu8(aj,ag,0x80)
buffer.fill(aj,ag+1,0,ah+8)

local ak=ag*8
local al=ag+1+ah+8

for am=7,0,-1 do
buffer.writeu8(aj,al+am,ak%256)
ak=ak//256
end

return aj,ai
end

local function DigestBlocks(af:buffer,ag:number)
local ah,ai=ac,ad
local aj,ak=aa,ab

local al,am,an,ao=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
local ap,aq,ar,as=0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
local at,au,av,aw=0xf3bcc908,0x84caa73b,0xfe94f82b,0x5f1d36f1
local ax,ay,az,aA=0xade682d1,0x2b3e6c1f,0xfb41bd6b,0x137e2179

for aB=0,ag-1,128 do
for aC=1,16 do
local aD=aB+(aC-1)*8
ah[aC]=bit32.byteswap(buffer.readu32(af,aD))
ai[aC]=bit32.byteswap(buffer.readu32(af,aD+4))
end

for aC=17,80 do
local aD,aE=ah[aC-15],ai[aC-15]
local aF,aG=ah[aC-2],ai[aC-2]

local aH=bit32.bxor(bit32.rshift(aE,1)+bit32.lshift(aD,31),bit32.rshift(aE,8)+bit32.lshift(aD,24),bit32.rshift(aE,7)+bit32.lshift(aD,25))
local aI=bit32.bxor(bit32.rshift(aG,19)+bit32.lshift(aF,13),bit32.lshift(aG,3)+bit32.rshift(aF,29),bit32.rshift(aG,6)+bit32.lshift(aF,26))

local aJ=ai[aC-16]+aH+ai[aC-7]+aI
ai[aC]=bit32.bor(aJ,0)
ah[aC]=bit32.bxor(bit32.rshift(aD,1)+bit32.lshift(aE,31),bit32.rshift(aD,8)+bit32.lshift(aE,24),bit32.rshift(aD,7))+
bit32.bxor(bit32.rshift(aF,19)+bit32.lshift(aG,13),bit32.lshift(aF,3)+bit32.rshift(aG,29),bit32.rshift(aF,6))+
ah[aC-16]+ah[aC-7]+aJ//0x100000000
end

local aC,aD=al,at
local aE,aF=am,au
local aG,aH=an,av
local aI,aJ=ao,aw
local aK,aL=ap,ax
local b,c=aq,ay
local d,e=ar,az
local f,g=as,aA

for h=1,79,2 do
local i=bit32.bxor(bit32.rshift(aL,14)+bit32.lshift(aK,18),bit32.rshift(aL,18)+bit32.lshift(aK,14),bit32.lshift(aL,23)+bit32.rshift(aK,9))
local j=bit32.bxor(bit32.rshift(aK,14)+bit32.lshift(aL,18),bit32.rshift(aK,18)+bit32.lshift(aL,14),bit32.lshift(aK,23)+bit32.rshift(aL,9))
local k=bit32.bxor(bit32.rshift(aD,28)+bit32.lshift(aC,4),bit32.lshift(aD,30)+bit32.rshift(aC,2),bit32.lshift(aD,25)+bit32.rshift(aC,7))
local l=bit32.bxor(bit32.rshift(aC,28)+bit32.lshift(aD,4),bit32.lshift(aC,30)+bit32.rshift(aD,2),bit32.lshift(aC,25)+bit32.rshift(aD,7))
local m=bit32.band(aL,c)+bit32.band(-1-aL,e)
local n=bit32.band(aK,b)+bit32.band(-1-aK,d)
local o=bit32.band(aH,aF)+bit32.band(aD,bit32.bxor(aH,aF))
local p=bit32.band(aG,aE)+bit32.band(aC,bit32.bxor(aG,aE))

local q=g+i+m+ak[h]+ai[h]
local r=f+j+n+aj[h]+ah[h]+q//0x100000000
q=bit32.bor(q,0)

f,g=d,e
d,e=b,c
b,c=aK,aL

local s=aJ+q
aK=aI+r+s//0x100000000
aL=bit32.bor(s,0)

aI,aJ=aG,aH
aG,aH=aE,aF
aE,aF=aC,aD

local t=q+k+o
aC=r+l+p+t//0x100000000
aD=bit32.bor(t,0)

local u=h+1
i=bit32.bxor(bit32.rshift(aL,14)+bit32.lshift(aK,18),bit32.rshift(aL,18)+bit32.lshift(aK,14),bit32.lshift(aL,23)+bit32.rshift(aK,9))
j=bit32.bxor(bit32.rshift(aK,14)+bit32.lshift(aL,18),bit32.rshift(aK,18)+bit32.lshift(aL,14),bit32.lshift(aK,23)+bit32.rshift(aL,9))
k=bit32.bxor(bit32.rshift(aD,28)+bit32.lshift(aC,4),bit32.lshift(aD,30)+bit32.rshift(aC,2),bit32.lshift(aD,25)+bit32.rshift(aC,7))
l=bit32.bxor(bit32.rshift(aC,28)+bit32.lshift(aD,4),bit32.lshift(aC,30)+bit32.rshift(aD,2),bit32.lshift(aC,25)+bit32.rshift(aD,7))
m=bit32.band(aL,c)+bit32.band(-1-aL,e)
n=bit32.band(aK,b)+bit32.band(-1-aK,d)
o=bit32.band(aH,aF)+bit32.band(aD,bit32.bxor(aH,aF))
p=bit32.band(aG,aE)+bit32.band(aC,bit32.bxor(aG,aE))

q=g+i+m+ak[u]+ai[u]
r=f+j+n+aj[u]+ah[u]+q//0x100000000
q=bit32.bor(q,0)

f,g=d,e
d,e=b,c
b,c=aK,aL

s=aJ+q
aK=aI+r+s//0x100000000
aL=bit32.bor(s,0)

aI,aJ=aG,aH
aG,aH=aE,aF
aE,aF=aC,aD

t=q+k+o
aC=r+l+p+t//0x100000000
aD=bit32.bor(t,0)
end

at=at+aD
al=bit32.bor(al+aC+at//0x100000000,0)
at=bit32.bor(at,0)

au=au+aF
am=bit32.bor(am+aE+au//0x100000000,0)
au=bit32.bor(au,0)

av=av+aH
an=bit32.bor(an+aG+av//0x100000000,0)
av=bit32.bor(av,0)

aw=aw+aJ
ao=bit32.bor(ao+aI+aw//0x100000000,0)
aw=bit32.bor(aw,0)

ax=ax+aL
ap=bit32.bor(ap+aK+ax//0x100000000,0)
ax=bit32.bor(ax,0)

ay=ay+c
aq=bit32.bor(aq+b+ay//0x100000000,0)
ay=bit32.bor(ay,0)

az=az+e
ar=bit32.bor(ar+d+az//0x100000000,0)
az=bit32.bor(az,0)

aA=aA+g
as=bit32.bor(as+f+aA//0x100000000,0)
aA=bit32.bor(aA,0)
end

buffer.writeu32(ae,0,al)
buffer.writeu32(ae,4,at)
buffer.writeu32(ae,8,am)
buffer.writeu32(ae,12,au)
buffer.writeu32(ae,16,an)
buffer.writeu32(ae,20,av)
buffer.writeu32(ae,24,ao)
buffer.writeu32(ae,28,aw)
buffer.writeu32(ae,32,ap)
buffer.writeu32(ae,36,ax)
buffer.writeu32(ae,40,aq)
buffer.writeu32(ae,44,ay)
buffer.writeu32(ae,48,ar)
buffer.writeu32(ae,52,az)
buffer.writeu32(ae,56,as)
buffer.writeu32(ae,60,aA)
end

local function SHA512(af:buffer):(string,buffer)
local ag,ah=PreProcess(af)
DigestBlocks(ag,ah)

local ai,aj=buffer.readu32(ae,0),buffer.readu32(ae,4)
local ak,al=buffer.readu32(ae,8),buffer.readu32(ae,12)
local am,an=buffer.readu32(ae,16),buffer.readu32(ae,20)
local ao,ap=buffer.readu32(ae,24),buffer.readu32(ae,28)
local aq,ar=buffer.readu32(ae,32),buffer.readu32(ae,36)
local as,at=buffer.readu32(ae,40),buffer.readu32(ae,44)
local au,av=buffer.readu32(ae,48),buffer.readu32(ae,52)
local aw,ax=buffer.readu32(ae,56),buffer.readu32(ae,60)

return string.format(
"%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
ai,aj,ak,al,am,an,ao,ap,
aq,ar,as,at,au,av,aw,ax
),ae
end

return SHA512 end function a.h():typeof(__modImpl())local aa=a.cache.h if not aa then aa={c=__modImpl()}a.cache.h=aa end return aa.c end end do local function __modImpl()




return{
SHA224=a.e(),
SHA256=a.f(),
SHA384=a.g(),
SHA512=a.h(),
}end function a.i():typeof(__modImpl())local aa=a.cache.i if not aa then aa={c=__modImpl()}a.cache.i=aa end return aa.c end end do local function __modImpl()























local aa={}

local ab=buffer.create(512)do
local ac="0123456789abcdef"
for ad=0,255 do
local ae=bit32.rshift(ad,4)
local af=ad%16

local ag=string.byte(ac,ae+1)
local ah=string.byte(ac,af+1)

local ai=ag+bit32.lshift(ah,8)
buffer.writeu16(ab,ad*2,ai)
end
end

local ac,ad=buffer.create(96),buffer.create(96)do
local ae=0
local af=29
local function GetNextBit():number
local ag=af%2
af=bit32.bxor((af-ag)//2,142*ag)

return ag
end

for ag=0,23 do
local ah=0
local ai:number

for aj=1,6 do
ai=if ai then ai*ai*2 else 1
ah+=GetNextBit()*ai
end

local aj=GetNextBit()*ai
buffer.writeu32(ad,ag*4,aj)
buffer.writeu32(ac,ag*4,ah+aj*ae)
end
end

local ae=buffer.create(100)
local af=buffer.create(100)

local function Keccak(ag:buffer,ah:buffer,ai:buffer,aj:number,ak:number,al:number):()
local am=al//8
local an,ao=ad,ac

for ap=aj,aj+ak-1,al do
for aq=0,(am-1)*4,4 do
local ar=ap+aq*2

buffer.writeu32(ag,aq,bit32.bxor(
buffer.readu32(ag,aq),
buffer.readu32(ai,ar)
))

buffer.writeu32(ah,aq,bit32.bxor(
buffer.readu32(ah,aq),
buffer.readu32(ai,ar+4)
))
end

local aq,ar=buffer.readu32(ag,0),buffer.readu32(ah,0)
local as,at=buffer.readu32(ag,4),buffer.readu32(ah,4)
local au,av=buffer.readu32(ag,8),buffer.readu32(ah,8)

local aw,ax=buffer.readu32(ag,12),buffer.readu32(ah,12)
local ay,az=buffer.readu32(ag,16),buffer.readu32(ah,16)
local aA,aB=buffer.readu32(ag,20),buffer.readu32(ah,20)

local aC,aD=buffer.readu32(ag,24),buffer.readu32(ah,24)
local aE,aF=buffer.readu32(ag,28),buffer.readu32(ah,28)
local aG,aH=buffer.readu32(ag,32),buffer.readu32(ah,32)

local aI,aJ=buffer.readu32(ag,36),buffer.readu32(ah,36)
local aK,aL=buffer.readu32(ag,40),buffer.readu32(ah,40)
local b,c=buffer.readu32(ag,44),buffer.readu32(ah,44)

local d,e=buffer.readu32(ag,48),buffer.readu32(ah,48)
local f,g=buffer.readu32(ag,52),buffer.readu32(ah,52)
local h,i=buffer.readu32(ag,56),buffer.readu32(ah,56)

local j,k=buffer.readu32(ag,60),buffer.readu32(ah,60)
local l,m=buffer.readu32(ag,64),buffer.readu32(ah,64)
local n,o=buffer.readu32(ag,68),buffer.readu32(ah,68)

local p,q=buffer.readu32(ag,72),buffer.readu32(ah,72)
local r,s=buffer.readu32(ag,76),buffer.readu32(ah,76)
local t,u=buffer.readu32(ag,80),buffer.readu32(ah,80)

local v,w=buffer.readu32(ag,84),buffer.readu32(ah,84)
local x,y=buffer.readu32(ag,88),buffer.readu32(ah,88)
local z,A=buffer.readu32(ag,92),buffer.readu32(ah,92)

local B,C=buffer.readu32(ag,96),buffer.readu32(ah,96)

for D=0,92,4 do
local E,F=bit32.bxor(aq,aA,aK,j,t),bit32.bxor(ar,aB,aL,k,u)
local G,H=bit32.bxor(as,aC,b,l,v),bit32.bxor(at,aD,c,m,w)
local I,J=bit32.bxor(au,aE,d,n,x),bit32.bxor(av,aF,e,o,y)
local K,L=bit32.bxor(aw,aG,f,p,z),bit32.bxor(ax,aH,g,q,A)
local M,N=bit32.bxor(ay,aI,h,r,B),bit32.bxor(az,aJ,i,s,C)

local O,P=bit32.bxor(E,I*2+J//2147483648),bit32.bxor(F,J*2+I//2147483648)
local Q,R=bit32.bxor(O,as),bit32.bxor(P,at)
local S,T=bit32.bxor(O,aC),bit32.bxor(P,aD)
local U,V=bit32.bxor(O,b),bit32.bxor(P,c)
local W,X=bit32.bxor(O,l),bit32.bxor(P,m)
local Y,Z=bit32.bxor(O,v),bit32.bxor(P,w)

as=S//1048576+(T*4096);at=T//1048576+(S*4096)
aC=W//524288+(X*8192);aD=X//524288+(W*8192)
b=Q*2+R//2147483648;c=R*2+Q//2147483648
l=U*1024+V//4194304;m=V*1024+U//4194304
v=Y*4+Z//1073741824;w=Z*4+Y//1073741824

O=bit32.bxor(G,K*2+L//2147483648);P=bit32.bxor(H,L*2+K//2147483648)
Q=bit32.bxor(O,au);R=bit32.bxor(P,av)
S=bit32.bxor(O,aE);T=bit32.bxor(P,aF)
U=bit32.bxor(O,d);V=bit32.bxor(P,e)
W=bit32.bxor(O,n);X=bit32.bxor(P,o)
Y=bit32.bxor(O,x);Z=bit32.bxor(P,y)

au=U//2097152+(V*2048);av=V//2097152+(U*2048)
aE=Y//8+bit32.bor(Z*536870912,0);aF=Z//8+bit32.bor(Y*536870912,0)
d=S*64+T//67108864;e=T*64+S//67108864
n=(W*32768)+X//131072;o=(X*32768)+W//131072
x=Q//4+bit32.bor(R*1073741824,0);y=R//4+bit32.bor(Q*1073741824,0)

O=bit32.bxor(I,M*2+N//2147483648);P=bit32.bxor(J,N*2+M//2147483648)
Q=bit32.bxor(O,aw);R=bit32.bxor(P,ax)
S=bit32.bxor(O,aG);T=bit32.bxor(P,aH)
U=bit32.bxor(O,f);V=bit32.bxor(P,g)
W=bit32.bxor(O,p);X=bit32.bxor(P,q)
Y=bit32.bxor(O,z);Z=bit32.bxor(P,A)

aw=bit32.bor(W*2097152,0)+X//2048;ax=bit32.bor(X*2097152,0)+W//2048
aG=bit32.bor(Q*268435456,0)+R//16;aH=bit32.bor(R*268435456,0)+Q//16
f=bit32.bor(U*33554432,0)+V//128;g=bit32.bor(V*33554432,0)+U//128
p=Y//256+bit32.bor(Z*16777216,0);q=Z//256+bit32.bor(Y*16777216,0)
z=S//512+bit32.bor(T*8388608,0);A=T//512+bit32.bor(S*8388608,0)
O=bit32.bxor(K,E*2+F//2147483648);P=bit32.bxor(L,F*2+E//2147483648)

Q=bit32.bxor(O,ay);R=bit32.bxor(P,az)
S=bit32.bxor(O,aI);T=bit32.bxor(P,aJ)
U=bit32.bxor(O,h);V=bit32.bxor(P,i)
W=bit32.bxor(O,r);X=bit32.bxor(P,s)
Y=bit32.bxor(O,B);Z=bit32.bxor(P,C)

ay=(Y*16384)+Z//262144;az=(Z*16384)+Y//262144
aI=bit32.bor(S*1048576,0)+T//4096;aJ=bit32.bor(T*1048576,0)+S//4096
h=W*256+X//16777216;i=X*256+W//16777216
r=bit32.bor(Q*134217728,0)+R//32;s=bit32.bor(R*134217728,0)+Q//32
B=U//33554432+V*128;C=V//33554432+U*128

O=bit32.bxor(M,G*2+H//2147483648);P=bit32.bxor(N,H*2+G//2147483648)
S=bit32.bxor(O,aA);T=bit32.bxor(P,aB)
U=bit32.bxor(O,aK);V=bit32.bxor(P,aL)
W=bit32.bxor(O,j);X=bit32.bxor(P,k)
Y=bit32.bxor(O,t);Z=bit32.bxor(P,u)
aA=U*8+V//536870912;aB=V*8+U//536870912
aK=(Y*262144)+Z//16384;aL=(Z*262144)+Y//16384
j=S//268435456+T*16;k=T//268435456+S*16
t=W//8388608+X*512;u=X//8388608+W*512
aq=bit32.bxor(O,aq);ar=bit32.bxor(P,ar)

aq,as,au,aw,ay=bit32.bxor(aq,bit32.band(-1-as,au)),bit32.bxor(as,bit32.band(-1-au,aw)),bit32.bxor(au,bit32.band(-1-aw,ay)),bit32.bxor(aw,bit32.band(-1-ay,aq)),bit32.bxor(ay,bit32.band(-1-aq,as))::number
ar,at,av,ax,az=bit32.bxor(ar,bit32.band(-1-at,av)),bit32.bxor(at,bit32.band(-1-av,ax)),bit32.bxor(av,bit32.band(-1-ax,az)),bit32.bxor(ax,bit32.band(-1-az,ar)),bit32.bxor(az,bit32.band(-1-ar,at))::number
aA,aC,aE,aG,aI=bit32.bxor(aG,bit32.band(-1-aI,aA)),bit32.bxor(aI,bit32.band(-1-aA,aC)),bit32.bxor(aA,bit32.band(-1-aC,aE)),bit32.bxor(aC,bit32.band(-1-aE,aG)),bit32.bxor(aE,bit32.band(-1-aG,aI))::number
aB,aD,aF,aH,aJ=bit32.bxor(aH,bit32.band(-1-aJ,aB)),bit32.bxor(aJ,bit32.band(-1-aB,aD)),bit32.bxor(aB,bit32.band(-1-aD,aF)),bit32.bxor(aD,bit32.band(-1-aF,aH)),bit32.bxor(aF,bit32.band(-1-aH,aJ))::number
aK,b,d,f,h=bit32.bxor(b,bit32.band(-1-d,f)),bit32.bxor(d,bit32.band(-1-f,h)),bit32.bxor(f,bit32.band(-1-h,aK)),bit32.bxor(h,bit32.band(-1-aK,b)),bit32.bxor(aK,bit32.band(-1-b,d))::number
aL,c,e,g,i=bit32.bxor(c,bit32.band(-1-e,g)),bit32.bxor(e,bit32.band(-1-g,i)),bit32.bxor(g,bit32.band(-1-i,aL)),bit32.bxor(i,bit32.band(-1-aL,c)),bit32.bxor(aL,bit32.band(-1-c,e))::number
j,l,n,p,r=bit32.bxor(r,bit32.band(-1-j,l)),bit32.bxor(j,bit32.band(-1-l,n)),bit32.bxor(l,bit32.band(-1-n,p)),bit32.bxor(n,bit32.band(-1-p,r)),bit32.bxor(p,bit32.band(-1-r,j))::number
k,m,o,q,s=bit32.bxor(s,bit32.band(-1-k,m)),bit32.bxor(k,bit32.band(-1-m,o)),bit32.bxor(m,bit32.band(-1-o,q)),bit32.bxor(o,bit32.band(-1-q,s)),bit32.bxor(q,bit32.band(-1-s,k))::number
t,v,x,z,B=bit32.bxor(x,bit32.band(-1-z,B)),bit32.bxor(z,bit32.band(-1-B,t)),bit32.bxor(B,bit32.band(-1-t,v)),bit32.bxor(t,bit32.band(-1-v,x)),bit32.bxor(v,bit32.band(-1-x,z))::number
u,w,y,A,C=bit32.bxor(y,bit32.band(-1-A,C)),bit32.bxor(A,bit32.band(-1-C,u)),bit32.bxor(C,bit32.band(-1-u,w)),bit32.bxor(u,bit32.band(-1-w,y)),bit32.bxor(w,bit32.band(-1-y,A))::number

aq=bit32.bxor(aq,buffer.readu32(ao,D))
ar=bit32.bxor(ar,buffer.readu32(an,D))
end

buffer.writeu32(ag,0,aq);buffer.writeu32(ah,0,ar)
buffer.writeu32(ag,4,as);buffer.writeu32(ah,4,at)
buffer.writeu32(ag,8,au);buffer.writeu32(ah,8,av)
buffer.writeu32(ag,12,aw);buffer.writeu32(ah,12,ax)
buffer.writeu32(ag,16,ay);buffer.writeu32(ah,16,az)
buffer.writeu32(ag,20,aA);buffer.writeu32(ah,20,aB)
buffer.writeu32(ag,24,aC);buffer.writeu32(ah,24,aD)
buffer.writeu32(ag,28,aE);buffer.writeu32(ah,28,aF)
buffer.writeu32(ag,32,aG);buffer.writeu32(ah,32,aH)
buffer.writeu32(ag,36,aI);buffer.writeu32(ah,36,aJ)
buffer.writeu32(ag,40,aK);buffer.writeu32(ah,40,aL)
buffer.writeu32(ag,44,b);buffer.writeu32(ah,44,c)
buffer.writeu32(ag,48,d);buffer.writeu32(ah,48,e)
buffer.writeu32(ag,52,f);buffer.writeu32(ah,52,g)
buffer.writeu32(ag,56,h);buffer.writeu32(ah,56,i)
buffer.writeu32(ag,60,j);buffer.writeu32(ah,60,k)
buffer.writeu32(ag,64,l);buffer.writeu32(ah,64,m)
buffer.writeu32(ag,68,n);buffer.writeu32(ah,68,o)
buffer.writeu32(ag,72,p);buffer.writeu32(ah,72,q)
buffer.writeu32(ag,76,r);buffer.writeu32(ah,76,s)
buffer.writeu32(ag,80,t);buffer.writeu32(ah,80,u)
buffer.writeu32(ag,84,v);buffer.writeu32(ah,84,w)
buffer.writeu32(ag,88,x);buffer.writeu32(ah,88,y)
buffer.writeu32(ag,92,z);buffer.writeu32(ah,92,A)
buffer.writeu32(ag,96,B);buffer.writeu32(ah,96,C)
end
end

local function ProcessSponge(ag:buffer,ah:number,ai:number,aj:number):(string,buffer)
local ak=(1600-ah)//8
buffer.fill(ae,0,0,100)
buffer.fill(af,0,0,100)

local al=ae
local am=af

local an:number=buffer.len(ag)
local ao:number=an+1

local ap=ao%ak
if ap~=0 then
ao+=(ak-ap)
end

local aq=buffer.create(ao)

if an>0 then
buffer.copy(aq,0,ag,0,an)
end

if ao-an==1 then
buffer.writeu8(aq,an,bit32.bor(aj,0x80))
else
buffer.writeu8(aq,an,aj)
if ao-an>2 then
buffer.fill(aq,an+1,0,ao-an-2)
end
buffer.writeu8(aq,ao-1,0x80)
end

Keccak(al,am,aq,0,ao,ak)

local ar=buffer.create(ai)
local as=buffer.len(ar)
local at=buffer.create(as*2)

local au=ab

local av=as%8
local aw=0
local ax=0

local ay=buffer.create(ak)
while ax<ai do
local az=math.min(ak,ai-ax)

for aA=0,az-1 do
local aB=ax+aA
if aB<ai then
local aC=aA//8
local aD=aA%8
local aE=aC*4

local aF
if aD<4 then
aF=bit32.extract(buffer.readu32(al,aE),aD*8,8)
else
aF=bit32.extract(buffer.readu32(am,aE),(aD-4)*8,8)
end
buffer.writeu8(ar,aB,aF)
end
end

ax+=az

if ax<ai then
Keccak(al,am,ay,0,ak,ak)
end
end

for az=0,as-av-1,8 do
local aA=buffer.readu16(au,buffer.readu8(ar,az)*2)
local aB=buffer.readu16(au,buffer.readu8(ar,az+1)*2)
local aC=buffer.readu16(au,buffer.readu8(ar,az+2)*2)
local aD=buffer.readu16(au,buffer.readu8(ar,az+3)*2)
local aE=buffer.readu16(au,buffer.readu8(ar,az+4)*2)
local aF=buffer.readu16(au,buffer.readu8(ar,az+5)*2)
local aG=buffer.readu16(au,buffer.readu8(ar,az+6)*2)
local aH=buffer.readu16(au,buffer.readu8(ar,az+7)*2)

buffer.writeu16(at,aw,aA)
buffer.writeu16(at,aw+2,aB)
buffer.writeu16(at,aw+4,aC)
buffer.writeu16(at,aw+6,aD)
buffer.writeu16(at,aw+8,aE)
buffer.writeu16(at,aw+10,aF)
buffer.writeu16(at,aw+12,aG)
buffer.writeu16(at,aw+14,aH)

aw+=16
end

for az=as-av,as-1 do
local aA=buffer.readu16(au,buffer.readu8(ar,az)*2)
buffer.writeu16(at,aw,aA)
aw+=2
end

return buffer.tostring(at),ar
end

function aa.SHA3_224(ag:buffer):(string,buffer)
return ProcessSponge(ag,448,28,0x06)
end

function aa.SHA3_256(ag:buffer):(string,buffer)
return ProcessSponge(ag,512,32,0x06)
end

function aa.SHA3_384(ag:buffer):(string,buffer)
return ProcessSponge(ag,768,48,0x06)
end

function aa.SHA3_512(ag:buffer):(string,buffer)
return ProcessSponge(ag,1024,64,0x06)
end

function aa.SHAKE128(ag:buffer,ah:number):(string,buffer)
return ProcessSponge(ag,256,ah,0x1F)
end

function aa.SHAKE256(ag:buffer,ah:number):(string,buffer)
return ProcessSponge(ag,512,ah,0x1F)
end

return aa end function a.j():typeof(__modImpl())local aa=a.cache.j if not aa then aa={c=__modImpl()}a.cache.j=aa end return aa.c end end do local function __modImpl()






















local function XXH32(aa:buffer,ab:number?):number
local ac,ad,ae=0x9e3779B1,40503,31153
local af,ag,ah=0x85ebca77,34283,51831
local ai,aj=49842,44605
local ak,al=10196,60207
local am,an,ao=0x165667b1,5718,26545

local ap=ab or 0
local aq=buffer.len(aa)
local ar:number
local as=0

if aq>=16 then
local at=ap+ac+af
local au=ap+af
local av=ap
local aw=ap-ac

while as<=aq-16 do
local ax=buffer.readu32(aa,as)
local ay=buffer.readu32(aa,as+4)
local az=buffer.readu32(aa,as+8)
local aA=buffer.readu32(aa,as+12)

local aB,aC=bit32.rshift(ax,16),bit32.band(ax,65535)
local aD=bit32.lshift((aB*ah)+(aC*ag),16)+(aC*ah)

local aE=bit32.lrotate(at+aD,13)
local aF,aG=bit32.rshift(aE,16),bit32.band(aE,65535)
at=bit32.lshift((aF*ae)+(aG*ad),16)+(aG*ae)

local aH,aI=bit32.rshift(ay,16),bit32.band(ay,65535)
local aJ=bit32.lshift((aH*ah)+(aI*ag),16)+(aI*ah)

local aK=bit32.lrotate(au+aJ,13)
local aL,b=bit32.rshift(aK,16),bit32.band(aK,65535)
au=bit32.lshift((aL*ae)+(b*ad),16)+(b*ae)

local c,d=bit32.rshift(az,16),bit32.band(az,65535)
local e=bit32.lshift((c*ah)+(d*ag),16)+(d*ah)

local f=bit32.lrotate(av+e,13)
local g,h=bit32.rshift(f,16),bit32.band(f,65535)
av=bit32.lshift((g*ae)+(h*ad),16)+(h*ae)

local i,j=bit32.rshift(aA,16),bit32.band(aA,65535)
local k=bit32.lshift((i*ah)+(j*ag),16)+(j*ah)

local l=bit32.lrotate(aw+k,13)
local m,n=bit32.rshift(l,16),bit32.band(l,65535)
aw=bit32.lshift((m*ae)+(n*ad),16)+(n*ae)

as+=16
end

ar=bit32.lrotate(at,1)+bit32.lrotate(au,7)+bit32.lrotate(av,12)+bit32.lrotate(aw,18)
else
ar=ap+am
end

ar+=aq

while as<=aq-4 do
if as+4<=buffer.len(aa)then
local at=buffer.readu32(aa,as)

local au,av=bit32.rshift(at,16),bit32.band(at,65535)
local aw=bit32.lshift((au*aj)+(av*ai),16)+(av*aj)

ar+=aw

local ax=bit32.lrotate(ar,17)
local ay,az=bit32.rshift(ax,16),bit32.band(ax,65535)
ar=bit32.lshift((ay*al)+(az*ak),16)+(az*al)
end
as+=4
end

while as<aq do
if as<buffer.len(aa)then
local at=buffer.readu8(aa,as)

local au,av=bit32.rshift(at,16),bit32.band(at,65535)
local aw=bit32.lshift((au*ao)+(av*an),16)+(av*ao)

ar+=aw

local ax=bit32.lrotate(ar,11)
local ay,az=bit32.rshift(ax,16),bit32.band(ax,65535)
ar=bit32.lshift((ay*ae)+(az*ad),16)+(az*ae)
end
as+=1
end

local at=bit32.bxor(ar,bit32.rshift(ar,15))
local au,av=bit32.rshift(at,16),bit32.band(at,65535)
ar=bit32.lshift((au*ah)+(av*ag),16)+(av*ah)

local aw=bit32.bxor(ar,bit32.rshift(ar,13))
local ax,ay=bit32.rshift(aw,16),bit32.band(aw,65535)
ar=bit32.lshift((ax*aj)+(ay*ai),16)+(ay*aj)

return bit32.bxor(ar,bit32.rshift(ar,16))
end

return XXH32 end function a.k():typeof(__modImpl())local aa=a.cache.k if not aa then aa={c=__modImpl()}a.cache.k=aa end return aa.c end end do local function __modImpl()





























local aa=128
local ab=64

local ac=1
local ad=64
local ae=64

local af={
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
0xf3bcc908,0x84caa73b,0xfe94f82b,0x5f1d36f1,0xade682d1,0x2b3e6c1f,0xfb41bd6b,0x137e2179
}

local ag={
1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
15,11,5,9,10,16,14,7,2,13,1,3,12,8,6,4,
12,9,13,1,6,3,16,14,11,15,4,7,8,2,10,5,
8,10,4,2,14,13,12,15,3,7,6,11,5,1,16,9,
10,1,6,8,3,5,11,16,15,2,12,13,7,9,4,14,
3,13,7,11,1,12,9,4,5,14,8,6,16,15,2,10,
13,6,2,16,15,14,5,11,1,8,7,4,10,3,9,12,
14,12,8,15,13,2,4,10,6,1,16,5,9,7,3,11,
7,16,15,10,12,4,1,9,13,3,14,8,2,5,11,6,
11,3,9,5,8,7,2,6,16,12,10,15,4,13,14,1,
1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
15,11,5,9,10,16,14,7,2,13,1,3,12,8,6,4
}

local ah,ai,aj,ak,al,am,an,ao=af[1],af[2],af[3],af[4],af[5],af[6],af[7],af[8]
local ap,aq,ar,as,at,au,av,aw=af[9],af[10],af[11],af[12],af[13],af[14],af[15],af[16]

local function ExtractWordsFromBlock(ax:buffer,ay:number,az:{number},aA:{number})
for aB=1,16 do
local aC=ay+(aB-1)*8
aA[aB]=buffer.readu32(ax,aC)
az[aB]=buffer.readu32(ax,aC+4)
end
end

local function ProcessCompressionRound(ax:{number},ay:{number},az:number,aA:boolean,aB:{number},aC:{number})
local aD,aE,aF,aG,aH,aI,aJ,aK=aB[1],aB[2],aB[3],aB[4],aB[5],aB[6],aB[7],aB[8]
local aL,b,c,d,e,f,g,h=aC[1],aC[2],aC[3],aC[4],aC[5],aC[6],aC[7],aC[8]

local i,j,k,l,m,n,o,p=ah,ai,aj,ak,al,am,an,ao
local q,r,s,t,u,v,w,x=ap,aq,ar,as,at,au,av,aw

m=bit32.bxor(m,az//0x100000000)
u=bit32.bxor(u,bit32.bor(az,0))
if aA then
o=bit32.bnot(o)
w=bit32.bnot(w)
end

local y,z,A,B,C=0,0,0,0,0
local D=ag

for E=1,12 do
local F=(E-1)*16

local G,H=D[F+1],D[F+2]
z,A=ax[G],ay[G]
B,C=ax[H],ay[H]

y=aL+e+A
aD+=aH+z+y//0x100000000
aL=bit32.bor(y,0)

y=m
m=bit32.bxor(u,aL)
u=bit32.bxor(y,aD)

y=q+u
i+=m+y//0x100000000
q=bit32.bor(y,0)

y=aH
aH=bit32.bxor(bit32.rshift(aH,24),bit32.lshift(e,8),bit32.rshift(i,24),bit32.lshift(q,8))
e=bit32.bxor(bit32.rshift(e,24),bit32.lshift(y,8),bit32.rshift(q,24),bit32.lshift(i,8))

y=aL+e+C
aD+=aH+B+y//0x100000000
aL=bit32.bor(y,0)

y=m
m=bit32.bxor(bit32.rshift(m,16),bit32.lshift(u,16),bit32.rshift(aD,16),bit32.lshift(aL,16))
u=bit32.bxor(bit32.rshift(u,16),bit32.lshift(y,16),bit32.rshift(aL,16),bit32.lshift(aD,16))

y=q+u
i+=m+y//0x100000000
q=bit32.bor(y,0)

y=aH
aH=bit32.bxor(bit32.lshift(aH,1),bit32.rshift(e,31),bit32.lshift(i,1),bit32.rshift(q,31))
e=bit32.bxor(bit32.lshift(e,1),bit32.rshift(y,31),bit32.lshift(q,1),bit32.rshift(i,31))

local I,J=D[F+3],D[F+4]
z,A=ax[I],ay[I]
B,C=ax[J],ay[J]

y=b+f+A
aE+=aI+z+y//0x100000000
b=bit32.bor(y,0)

y=n
n=bit32.bxor(v,b)
v=bit32.bxor(y,aE)

y=r+v
j+=n+y//0x100000000
r=bit32.bor(y,0)

y=aI
aI=bit32.bxor(bit32.rshift(aI,24),bit32.lshift(f,8),bit32.rshift(j,24),bit32.lshift(r,8))
f=bit32.bxor(bit32.rshift(f,24),bit32.lshift(y,8),bit32.rshift(r,24),bit32.lshift(j,8))

y=b+f+C
aE+=aI+B+y//0x100000000
b=bit32.bor(y,0)

y=n
n=bit32.bxor(bit32.rshift(n,16),bit32.lshift(v,16),bit32.rshift(aE,16),bit32.lshift(b,16))
v=bit32.bxor(bit32.rshift(v,16),bit32.lshift(y,16),bit32.rshift(b,16),bit32.lshift(aE,16))

y=r+v
j+=n+y//0x100000000
r=bit32.bor(y,0)

y=aI
aI=bit32.bxor(bit32.lshift(aI,1),bit32.rshift(f,31),bit32.lshift(j,1),bit32.rshift(r,31))
f=bit32.bxor(bit32.lshift(f,1),bit32.rshift(y,31),bit32.lshift(r,1),bit32.rshift(j,31))

local K,L=D[F+5],D[F+6]
z,A=ax[K],ay[K]
B,C=ax[L],ay[L]

y=c+g+A
aF+=aJ+z+y//0x100000000
c=bit32.bor(y,0)

y=o
o=bit32.bxor(w,c)
w=bit32.bxor(y,aF)

y=s+w
k+=o+y//0x100000000
s=bit32.bor(y,0)

y=aJ
aJ=bit32.bxor(bit32.rshift(aJ,24),bit32.lshift(g,8),bit32.rshift(k,24),bit32.lshift(s,8))
g=bit32.bxor(bit32.rshift(g,24),bit32.lshift(y,8),bit32.rshift(s,24),bit32.lshift(k,8))

y=c+g+C
aF+=aJ+B+y//0x100000000
c=bit32.bor(y,0)

y=o
o=bit32.bxor(bit32.rshift(o,16),bit32.lshift(w,16),bit32.rshift(aF,16),bit32.lshift(c,16))
w=bit32.bxor(bit32.rshift(w,16),bit32.lshift(y,16),bit32.rshift(c,16),bit32.lshift(aF,16))

y=s+w
k+=o+y//0x100000000
s=bit32.bor(y,0)

y=aJ
aJ=bit32.bxor(bit32.lshift(aJ,1),bit32.rshift(g,31),bit32.lshift(k,1),bit32.rshift(s,31))
g=bit32.bxor(bit32.lshift(g,1),bit32.rshift(y,31),bit32.lshift(s,1),bit32.rshift(k,31))

local M,N=D[F+7],D[F+8]
z,A=ax[M],ay[M]
B,C=ax[N],ay[N]

y=d+h+A
aG+=aK+z+y//0x100000000
d=bit32.bor(y,0)

y=p
p=bit32.bxor(x,d)
x=bit32.bxor(y,aG)

y=t+x
l+=p+y//0x100000000
t=bit32.bor(y,0)

y=aK
aK=bit32.bxor(bit32.rshift(aK,24),bit32.lshift(h,8),bit32.rshift(l,24),bit32.lshift(t,8))
h=bit32.bxor(bit32.rshift(h,24),bit32.lshift(y,8),bit32.rshift(t,24),bit32.lshift(l,8))

y=d+h+C
aG+=aK+B+y//0x100000000
d=bit32.bor(y,0)

y=p
p=bit32.bxor(bit32.rshift(p,16),bit32.lshift(x,16),bit32.rshift(aG,16),bit32.lshift(d,16))
x=bit32.bxor(bit32.rshift(x,16),bit32.lshift(y,16),bit32.rshift(d,16),bit32.lshift(aG,16))

y=t+x
l+=p+y//0x100000000
t=bit32.bor(y,0)

y=aK
aK=bit32.bxor(bit32.lshift(aK,1),bit32.rshift(h,31),bit32.lshift(l,1),bit32.rshift(t,31))
h=bit32.bxor(bit32.lshift(h,1),bit32.rshift(y,31),bit32.lshift(t,1),bit32.rshift(l,31))

local O,P=D[F+9],D[F+10]
z,A=ax[O],ay[O]
B,C=ax[P],ay[P]

y=aL+f+A
aD+=aI+z+y//0x100000000
aL=bit32.bor(y,0)

y=p
p=bit32.bxor(x,aL)
x=bit32.bxor(y,aD)

y=s+x
k+=p+y//0x100000000
s=bit32.bor(y,0)

y=aI
aI=bit32.bxor(bit32.rshift(aI,24),bit32.lshift(f,8),bit32.rshift(k,24),bit32.lshift(s,8))
f=bit32.bxor(bit32.rshift(f,24),bit32.lshift(y,8),bit32.rshift(s,24),bit32.lshift(k,8))

y=aL+f+C
aD+=aI+B+y//0x100000000
aL=bit32.bor(y,0)

y=p
p=bit32.bxor(bit32.rshift(p,16),bit32.lshift(x,16),bit32.rshift(aD,16),bit32.lshift(aL,16))
x=bit32.bxor(bit32.rshift(x,16),bit32.lshift(y,16),bit32.rshift(aL,16),bit32.lshift(aD,16))

y=s+x
k+=p+y//0x100000000
s=bit32.bor(y,0)

y=aI
aI=bit32.bxor(bit32.lshift(aI,1),bit32.rshift(f,31),bit32.lshift(k,1),bit32.rshift(s,31))
f=bit32.bxor(bit32.lshift(f,1),bit32.rshift(y,31),bit32.lshift(s,1),bit32.rshift(k,31))

local Q,R=D[F+11],D[F+12]
z,A=ax[Q],ay[Q]
B,C=ax[R],ay[R]

y=b+g+A
aE+=aJ+z+y//0x100000000
b=bit32.bor(y,0)

y=m
m=bit32.bxor(u,b)
u=bit32.bxor(y,aE)

y=t+u
l+=m+y//0x100000000
t=bit32.bor(y,0)

y=aJ
aJ=bit32.bxor(bit32.rshift(aJ,24),bit32.lshift(g,8),bit32.rshift(l,24),bit32.lshift(t,8))
g=bit32.bxor(bit32.rshift(g,24),bit32.lshift(y,8),bit32.rshift(t,24),bit32.lshift(l,8))

y=b+g+C
aE+=aJ+B+y//0x100000000
b=bit32.bor(y,0)

y=m
m=bit32.bxor(bit32.rshift(m,16),bit32.lshift(u,16),bit32.rshift(aE,16),bit32.lshift(b,16))
u=bit32.bxor(bit32.rshift(u,16),bit32.lshift(y,16),bit32.rshift(b,16),bit32.lshift(aE,16))

y=t+u
l+=m+y//0x100000000
t=bit32.bor(y,0)

y=aJ
aJ=bit32.bxor(bit32.lshift(aJ,1),bit32.rshift(g,31),bit32.lshift(l,1),bit32.rshift(t,31))
g=bit32.bxor(bit32.lshift(g,1),bit32.rshift(y,31),bit32.lshift(t,1),bit32.rshift(l,31))

local S,T=D[F+13],D[F+14]
z,A=ax[S],ay[S]
B,C=ax[T],ay[T]

y=c+h+A
aF+=aK+z+y//0x100000000
c=bit32.bor(y,0)

y=n
n=bit32.bxor(v,c)
v=bit32.bxor(y,aF)

y=q+v
i+=n+y//0x100000000
q=bit32.bor(y,0)

y=aK
aK=bit32.bxor(bit32.rshift(aK,24),bit32.lshift(h,8),bit32.rshift(i,24),bit32.lshift(q,8))
h=bit32.bxor(bit32.rshift(h,24),bit32.lshift(y,8),bit32.rshift(q,24),bit32.lshift(i,8))

y=c+h+C
aF+=aK+B+y//0x100000000
c=bit32.bor(y,0)

y=n
n=bit32.bxor(bit32.rshift(n,16),bit32.lshift(v,16),bit32.rshift(aF,16),bit32.lshift(c,16))
v=bit32.bxor(bit32.rshift(v,16),bit32.lshift(y,16),bit32.rshift(c,16),bit32.lshift(aF,16))

y=q+v
i+=n+y//0x100000000
q=bit32.bor(y,0)

y=aK
aK=bit32.bxor(bit32.lshift(aK,1),bit32.rshift(h,31),bit32.lshift(i,1),bit32.rshift(q,31))
h=bit32.bxor(bit32.lshift(h,1),bit32.rshift(y,31),bit32.lshift(q,1),bit32.rshift(i,31))

local U,V=D[F+15],D[F+16]
z,A=ax[U],ay[U]
B,C=ax[V],ay[V]

y=d+e+A
aG+=aH+z+y//0x100000000
d=bit32.bor(y,0)

y=o
o=bit32.bxor(w,d)
w=bit32.bxor(y,aG)

y=r+w
j+=o+y//0x100000000
r=bit32.bor(y,0)

y=aH
aH=bit32.bxor(bit32.rshift(aH,24),bit32.lshift(e,8),bit32.rshift(j,24),bit32.lshift(r,8))
e=bit32.bxor(bit32.rshift(e,24),bit32.lshift(y,8),bit32.rshift(r,24),bit32.lshift(j,8))

y=d+e+C
aG+=aH+B+y//0x100000000
d=bit32.bor(y,0)

y=o
o=bit32.bxor(bit32.rshift(o,16),bit32.lshift(w,16),bit32.rshift(aG,16),bit32.lshift(d,16))
w=bit32.bxor(bit32.rshift(w,16),bit32.lshift(y,16),bit32.rshift(d,16),bit32.lshift(aG,16))

y=r+w
j+=o+y//0x100000000
r=bit32.bor(y,0)

y=aH
aH=bit32.bxor(bit32.lshift(aH,1),bit32.rshift(e,31),bit32.lshift(j,1),bit32.rshift(r,31))
e=bit32.bxor(bit32.lshift(e,1),bit32.rshift(y,31),bit32.lshift(r,1),bit32.rshift(j,31))
end

aB[1]=bit32.bxor(aB[1],aD,i)
aC[1]=bit32.bxor(aC[1],aL,q)
aB[2]=bit32.bxor(aB[2],aE,j)
aC[2]=bit32.bxor(aC[2],b,r)
aB[3]=bit32.bxor(aB[3],aF,k)
aC[3]=bit32.bxor(aC[3],c,s)
aB[4]=bit32.bxor(aB[4],aG,l)
aC[4]=bit32.bxor(aC[4],d,t)
aB[5]=bit32.bxor(aB[5],aH,m)
aC[5]=bit32.bxor(aC[5],e,u)
aB[6]=bit32.bxor(aB[6],aI,n)
aC[6]=bit32.bxor(aC[6],f,v)
aB[7]=bit32.bxor(aB[7],aJ,o)
aC[7]=bit32.bxor(aC[7],g,w)
aB[8]=bit32.bxor(aB[8],aK,p)
aC[8]=bit32.bxor(aC[8],h,x)
end

local function HashDigest(ax:buffer,ay:number,az:buffer?):(string,buffer)
local aA=az and buffer.len(az)or 0
local aB=buffer.len(ax)

local aC={ah,ai,aj,ak,al,am,an,ao}
local aD={ap,aq,ar,as,at,au,av,aw}

aD[1]=bit32.bxor(aD[1],0x01010000,bit32.lshift(aA,8),ay)

local aE=table.create(16)::{number}
local aF=table.create(16)::{number}
local aG=aA>0 and 128 or 0

if aA>0 and az then
local aH=buffer.create(aa)
buffer.copy(aH,0,az)
ExtractWordsFromBlock(aH,0,aE,aF)
ProcessCompressionRound(aE,aF,aG,aB==0,aC,aD)
end

local aH=aB%aa
local aI=aH==0 and aa or aH

for aJ=0,aB-aI-1,aa do
ExtractWordsFromBlock(ax,aJ,aE,aF)
aG+=aa
ProcessCompressionRound(aE,aF,aG,false,aC,aD)
end

if aA==0 or aB>0 then
local aJ=buffer.create(aa)
local aK=math.min(aI,aB)
local aL=math.max(0,aB-aI)
if aK>0 then
buffer.copy(aJ,0,ax,aL,aK)
end

ExtractWordsFromBlock(aJ,0,aE,aF)
ProcessCompressionRound(aE,aF,aG+aK,true,aC,aD)
end

local aJ=buffer.create(ay)
local aK=0

for aL=1,8 do
if aK+4<=ay then
buffer.writeu32(aJ,aK,aD[aL])
aK+=4
end

if aK+4<=ay then
buffer.writeu32(aJ,aK,aC[aL])
aK+=4
end

if aK>=ay then
break
end
end

local aL=string.format(
"%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
bit32.byteswap(aD[1]),bit32.byteswap(aC[1]),
bit32.byteswap(aD[2]),bit32.byteswap(aC[2]),
bit32.byteswap(aD[3]),bit32.byteswap(aC[3]),
bit32.byteswap(aD[4]),bit32.byteswap(aC[4]),
bit32.byteswap(aD[5]),bit32.byteswap(aC[5]),
bit32.byteswap(aD[6]),bit32.byteswap(aC[6]),
bit32.byteswap(aD[7]),bit32.byteswap(aC[7]),
bit32.byteswap(aD[8]),bit32.byteswap(aC[8])
)

return string.sub(aL,1,ay*2),aJ
end

local function BLAKE2b(ax:buffer,ay:number?,az:buffer?):(string,buffer)
if ax==nil then
error("InputData cannot be nil",2)
end

if typeof(ax)~="buffer"then
error(`InputData must be a buffer, got {typeof(ax)}`,2)
end

if ay then
if typeof(ay)~="number"then
error(`OutputLength must be a number, got {typeof(ay)}`,2)
end

if ay~=math.floor(ay)then
error(`OutputLength must be an integer, got {ay}`,2)
end

if ay<ac or ay>ad then
error(`OutputLength must be between {ac} and {ad} bytes, got {ay} bytes`,2)
end
end

if az then
if typeof(az)~="buffer"then
error(`KeyData must be a buffer, got {typeof(az)}`,2)
end

local aA=buffer.len(az)
if aA==0 then
error("KeyData cannot be empty",2)
end

if aA>ae then
error(`KeyData must be at most {ae} bytes long, got {aA} bytes`,2)
end
end

return HashDigest(ax,ay or ab,az)
end

return BLAKE2b end function a.l():typeof(__modImpl())local aa=a.cache.l if not aa then aa={c=__modImpl()}a.cache.l=aa end return aa.c end end do local function __modImpl()




























local aa={}

local ab=64
local ac=32
local ad=64
local ae=64
local af=ae*ac

local ag=32
local ah=1
local ai=4294967295

local aj=0x01
local ak=0x02
local al=0x04
local am=0x08
local an=0x10
local ao=0x20
local ap=0x40

local aq=buffer.create(ac)do
local ar={
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
}
for as,at in ipairs(ar)do
buffer.writeu32(aq,(as-1)*4,at)
end
end

local ar=buffer.create(512)do
local as="0123456789abcdef"
for at=0,255 do
local au=bit32.rshift(at,4)
local av=at%16

local aw=string.byte(as,au+1)
local ax=string.byte(as,av+1)

local ay=aw+bit32.lshift(ax,8)
buffer.writeu16(ar,at*2,ay)
end
end

local function Compress(as:buffer,at:buffer,au:number,av:number,aw:number,ax:boolean?):buffer
local ay=buffer.readu32(as,0)
local az=buffer.readu32(as,4)
local aA=buffer.readu32(as,8)
local aB=buffer.readu32(as,12)
local aC=buffer.readu32(as,16)
local aD=buffer.readu32(as,20)
local aE=buffer.readu32(as,24)
local aF=buffer.readu32(as,28)

local aG,aH,aI,aJ=ay,az,aA,aB
local aK,aL,b,c=aC,aD,aE,aF
local d,e,f,g=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a

local h=au%(4294967296)
local i=(au-h)*(2.3283064365386963E-10)

local j=buffer.readu32(at,0)
local k=buffer.readu32(at,4)
local l=buffer.readu32(at,8)
local m=buffer.readu32(at,12)
local n=buffer.readu32(at,16)
local o=buffer.readu32(at,20)
local p=buffer.readu32(at,24)
local q=buffer.readu32(at,28)
local r=buffer.readu32(at,32)
local s=buffer.readu32(at,36)
local t=buffer.readu32(at,40)
local u=buffer.readu32(at,44)
local v=buffer.readu32(at,48)
local w=buffer.readu32(at,52)
local x=buffer.readu32(at,56)
local y=buffer.readu32(at,60)

local z
for A=1,7 do
aG+=aK+j;h=bit32.lrotate(bit32.bxor(h,aG),16)
d+=h;aK=bit32.lrotate(bit32.bxor(aK,d),20)
aG+=aK+k;h=bit32.lrotate(bit32.bxor(h,aG),24)
d+=h;aK=bit32.lrotate(bit32.bxor(aK,d),25)

aH+=aL+l;i=bit32.lrotate(bit32.bxor(i,aH),16)
e+=i;aL=bit32.lrotate(bit32.bxor(aL,e),20)
aH+=aL+m;i=bit32.lrotate(bit32.bxor(i,aH),24)
e+=i;aL=bit32.lrotate(bit32.bxor(aL,e),25)

aI+=b+n;av=bit32.lrotate(bit32.bxor(av,aI),16)
f+=av;b=bit32.lrotate(bit32.bxor(b,f),20)
aI+=b+o;av=bit32.lrotate(bit32.bxor(av,aI),24)
f+=av;b=bit32.lrotate(bit32.bxor(b,f),25)

aJ+=c+p;aw=bit32.lrotate(bit32.bxor(aw,aJ),16)
g+=aw;c=bit32.lrotate(bit32.bxor(c,g),20)
aJ+=c+q;aw=bit32.lrotate(bit32.bxor(aw,aJ),24)
g+=aw;c=bit32.lrotate(bit32.bxor(c,g),25)

aG+=aL+r;aw=bit32.lrotate(bit32.bxor(aw,aG),16)
f+=aw;aL=bit32.lrotate(bit32.bxor(aL,f),20)
aG+=aL+s;aw=bit32.lrotate(bit32.bxor(aw,aG),24)
f+=aw;aL=bit32.lrotate(bit32.bxor(aL,f),25)

aH+=b+t;h=bit32.lrotate(bit32.bxor(h,aH),16)
g+=h;b=bit32.lrotate(bit32.bxor(b,g),20)
aH+=b+u;h=bit32.lrotate(bit32.bxor(h,aH),24)
g+=h;b=bit32.lrotate(bit32.bxor(b,g),25)

aI+=c+v;i=bit32.lrotate(bit32.bxor(i,aI),16)
d+=i;c=bit32.lrotate(bit32.bxor(c,d),20)
aI+=c+w;i=bit32.lrotate(bit32.bxor(i,aI),24)
d+=i;c=bit32.lrotate(bit32.bxor(c,d),25)

aJ+=aK+x;av=bit32.lrotate(bit32.bxor(av,aJ),16)
e+=av;aK=bit32.lrotate(bit32.bxor(aK,e),20)
aJ+=aK+y;av=bit32.lrotate(bit32.bxor(av,aJ),24)
e+=av;aK=bit32.lrotate(bit32.bxor(aK,e),25)

if A~=7 then
z=l
l=m
m=t
t=v
v=s
s=u
u=o
o=j
j=z

z=p
p=n
n=q
q=w
w=x
x=y
y=r
r=k
k=z
end
end

if ax then
local A=buffer.create(ad)
buffer.writeu32(A,0,bit32.bxor(aG,d))
buffer.writeu32(A,4,bit32.bxor(aH,e))
buffer.writeu32(A,8,bit32.bxor(aI,f))
buffer.writeu32(A,12,bit32.bxor(aJ,g))
buffer.writeu32(A,16,bit32.bxor(aK,h))
buffer.writeu32(A,20,bit32.bxor(aL,i))
buffer.writeu32(A,24,bit32.bxor(b,av))
buffer.writeu32(A,28,bit32.bxor(c,aw))

buffer.writeu32(A,32,bit32.bxor(d,ay))
buffer.writeu32(A,36,bit32.bxor(e,az))
buffer.writeu32(A,40,bit32.bxor(f,aA))
buffer.writeu32(A,44,bit32.bxor(g,aB))
buffer.writeu32(A,48,bit32.bxor(h,aC))
buffer.writeu32(A,52,bit32.bxor(i,aD))
buffer.writeu32(A,56,bit32.bxor(av,aE))
buffer.writeu32(A,60,bit32.bxor(aw,aF))

return A
else
local A=buffer.create(ac)
buffer.writeu32(A,0,bit32.bxor(aG,d))
buffer.writeu32(A,4,bit32.bxor(aH,e))
buffer.writeu32(A,8,bit32.bxor(aI,f))
buffer.writeu32(A,12,bit32.bxor(aJ,g))
buffer.writeu32(A,16,bit32.bxor(aK,h))
buffer.writeu32(A,20,bit32.bxor(aL,i))
buffer.writeu32(A,24,bit32.bxor(b,av))
buffer.writeu32(A,28,bit32.bxor(c,aw))

return A
end
end

local function ProcessMessage(as:buffer,at:number,au:buffer,av:number):buffer
local aw=buffer.len(au)
local ax=buffer.create(af)
local ay=buffer.create(ac)

local az=0
local aA=0

local aB=0
local aC=0

local aD=ab
local aE=ac
local aF=ad

local aG=aj
local aH=aj
local aI=ak

local aJ=al
local aK=am
local aL=at+aJ

local b=buffer.create(aD)
local c=buffer.create(aE)
local d=buffer.create(aF)
local e=buffer.create(aE)
local f=buffer.create(aF)

buffer.copy(ay,0,as,0,aE)

for g=0,aw-aD-1,aD do
buffer.copy(b,0,au,g,aD)
local h=at+aG+aC
ay=Compress(ay,b,aA,aD,h)
aG=0
aB+=1

if aB==15 then
aC=aI
elseif aB==16 then
local i=ay
local j=aA+1

while j%2==0 do
az-=1
buffer.copy(c,0,ax,az*aE,aE)
buffer.copy(d,0,c,0,aE)
buffer.copy(d,aE,i,0,aE)
i=Compress(as,d,0,aD,aL)
j/=2
end

buffer.copy(ax,az*aE,i,0,aE)
az+=1

buffer.copy(ay,0,as,0,aE)
aG=aH
aA+=1
aB=0
aC=0
end
end

local g=aw==0 and 0 or((aw-1)%aD+1)
local h=buffer.create(aD)
if g>0 then
buffer.copy(h,0,au,aw-g,g)
end

local i:buffer
local j:buffer
local k:number
local l:number

if aA>0 then
local m=at+aG+aI
local n=Compress(ay,h,aA,g,m)
for o=az,2,-1 do
buffer.copy(e,0,ax,(o-1)*aE,aE)
buffer.copy(f,0,e,0,aE)
buffer.copy(f,aE,n,0,aE)
n=Compress(as,f,0,aD,aL)
end

i=as
local o=buffer.create(aE)
buffer.copy(o,0,ax,0,aE)
j=buffer.create(aF)

buffer.copy(j,0,o,0,aE)
buffer.copy(j,aE,n,0,aE)

k=aD
l=at+aK+aJ
else
i=ay
j=h
k=g
l=at+aG+aI+aK
end

local m=buffer.create(av)
local n=0
for o=0,av//aD do
local p=Compress(i,j,o,k,l,true)
local q=math.min(aD,av-n)
buffer.copy(m,n,p,0,q)
n+=q
if n>=av then
break
end
end

return m
end

local function ToHex(as:buffer):string
local at=buffer.len(as)
local au=buffer.create(at*2)

local av=ar

local aw=at%8
local ax=0

for ay=0,at-aw-1,8 do
local az=buffer.readu16(av,buffer.readu8(as,ay)*2)
local aA=buffer.readu16(av,buffer.readu8(as,ay+1)*2)
local aB=buffer.readu16(av,buffer.readu8(as,ay+2)*2)
local aC=buffer.readu16(av,buffer.readu8(as,ay+3)*2)
local aD=buffer.readu16(av,buffer.readu8(as,ay+4)*2)
local aE=buffer.readu16(av,buffer.readu8(as,ay+5)*2)
local aF=buffer.readu16(av,buffer.readu8(as,ay+6)*2)
local aG=buffer.readu16(av,buffer.readu8(as,ay+7)*2)

buffer.writeu16(au,ax,az)
buffer.writeu16(au,ax+2,aA)
buffer.writeu16(au,ax+4,aB)
buffer.writeu16(au,ax+6,aC)
buffer.writeu16(au,ax+8,aD)
buffer.writeu16(au,ax+10,aE)
buffer.writeu16(au,ax+12,aF)
buffer.writeu16(au,ax+14,aG)

ax+=16
end

for ay=at-aw,at-1 do
local az=buffer.readu16(av,buffer.readu8(as,ay)*2)
buffer.writeu16(au,ax,az)
ax+=2
end

return buffer.tostring(au)
end

function aa.Digest(as:buffer,at:number?):(string,buffer)
if as==nil then
error("Message cannot be nil",2)
end

if typeof(as)~="buffer"then
error(`Message must be a buffer, got {typeof(as)}`,2)
end

if at then
if typeof(at)~="number"then
error(`Length must be a number, got {typeof(at)}`,2)
end

if at~=math.floor(at)then
error(`Length must be an integer, got {at}`,2)
end

if at<ah then
error(`Length must be at least {ah} byte, got {at} bytes`,2)
end

if at>ai then
error(`Length must be at most {ai} bytes, got {at} bytes`,2)
end
end

local au=ProcessMessage(aq,0,as,at or 32)

return ToHex(au),au
end

function aa.DigestKeyed(as:buffer,at:buffer,au:number?):(string,buffer)
if at==nil then
error("Key cannot be nil",2)
end

if typeof(at)~="buffer"then
error(`Key must be a buffer, got {typeof(at)}`,2)
end

local av=buffer.len(at)
if av~=ag then
error(`Key must be exactly {ag} bytes long, got {av} bytes`,2)
end

if as==nil then
error("Message cannot be nil",2)
end
if typeof(as)~="buffer"then
error(`Message must be a buffer, got {typeof(as)}`,2)
end

if au then
if typeof(au)~="number"then
error(`Length must be a number, got {typeof(au)}`,2)
end
if au~=math.floor(au)then
error(`Length must be an integer, got {au}`,2)
end
if au<ah then
error(`Length must be at least {ah} byte, got {au} bytes`,2)
end
if au>ai then
error(`Length must be at most {ai} bytes, got {au} bytes`,2)
end
end

local aw=ProcessMessage(at,an,as,au or 32)

return ToHex(aw),aw
end

function aa.DeriveKey(as:buffer):(buffer,number?)->(string,buffer)
if as==nil then
error("Context cannot be nil",2)
end

if typeof(as)~="buffer"then
error(`Context must be a buffer, got {typeof(as)}`,2)
end

local at=ProcessMessage(aq,ao,as,32)

return function(au:buffer,av:number?):(string,buffer)
if au==nil then
error("Material cannot be nil",2)
end

if typeof(au)~="buffer"then
error(`Material must be a buffer, got {typeof(au)}`,2)
end

if av then
if typeof(av)~="number"then
error(`Length must be a number, got {typeof(av)}`,2)
end

if av~=math.floor(av)then
error(`Length must be an integer, got {av}`,2)
end

if av<ah then
error(`Length must be at least {ah} byte, got {av} bytes`,2)
end

if av>ai then
error(`Length must be at most {ai} bytes, got {av} bytes`,2)
end
end

local aw=ProcessMessage(at,ap,au,av or 32)

return ToHex(aw),aw
end
end

return aa end function a.m():typeof(__modImpl())local aa=a.cache.m if not aa then aa={c=__modImpl()}a.cache.m=aa end return aa.c end end do local function __modImpl()
























local function Mul32(aa:number,ab:number):number
local ac=bit32.rshift(aa,16)
local ad=bit32.band(aa,0xFFFF)
local ae=bit32.rshift(ab,16)
local af=bit32.band(ab,0xFFFF)

local ag=ad*af
local ah=bit32.lshift(ac*af,16)
local ai=bit32.lshift(ad*ae,16)

local aj=bit32.bor(ag+ah,0)
return bit32.bor(aj+ai,0)
end

local function FMix32(aa:number):number
aa=Mul32(bit32.bxor(aa,bit32.rshift(aa,16)),0x85ebca6b)
aa=Mul32(bit32.bxor(aa,bit32.rshift(aa,13)),0xc2b2ae35)
aa=bit32.bxor(aa,bit32.rshift(aa,16))
return aa
end

local function MurmurHash3(aa:buffer,ab:number?):number
local ac=0xcc9e2d51
local ad=0x1b873593

local ae=bit32.bor(ab or 0,0)
local af=buffer.len(aa)
local ag=af//4
local ah=ag//4
local ai=0

for aj=1,ah do
local ak=buffer.readu32(aa,ai)
ak=Mul32(bit32.lrotate(Mul32(ak,0xcc9e2d51),15),0x1b873593)
ae=bit32.bor(bit32.lrotate(bit32.bxor(ae,ak),13)*5+0xe6546b64,0)

local al=buffer.readu32(aa,ai+4)
al=Mul32(bit32.lrotate(Mul32(al,0xcc9e2d51),15),0x1b873593)
ae=bit32.bor(bit32.lrotate(bit32.bxor(ae,al),13)*5+0xe6546b64,0)

local am=buffer.readu32(aa,ai+8)
am=Mul32(bit32.lrotate(Mul32(am,0xcc9e2d51),15),0x1b873593)
ae=bit32.bor(bit32.lrotate(bit32.bxor(ae,am),13)*5+0xe6546b64,0)

local an=buffer.readu32(aa,ai+12)
an=Mul32(bit32.lrotate(Mul32(an,0xcc9e2d51),15),0x1b873593)
ae=bit32.bor(bit32.lrotate(bit32.bxor(ae,an),13)*5+0xe6546b64,0)

ai+=16
end

local aj=ag%4
for ak=1,aj do
local al=buffer.readu32(aa,ai)
al=Mul32(al,0xcc9e2d51)
al=bit32.lrotate(al,15)
al=Mul32(al,0x1b873593)
ae=bit32.bxor(ae,al)
ae=bit32.lrotate(ae,13)
ae=bit32.bor(ae*5+0xe6546b64,0)

ai+=4
end

local ak=af%4
if ak>0 then
local al=0

if ak>=3 then
al=bit32.bxor(al,bit32.lshift(buffer.readu8(aa,ai+2),16))
end

if ak>=2 then
al=bit32.bxor(al,bit32.lshift(buffer.readu8(aa,ai+1),8))
end

al=bit32.bxor(al,buffer.readu8(aa,ai))

al=Mul32(al,ac)
al=bit32.lrotate(al,15)
al=Mul32(al,ad)
ae=bit32.bxor(ae,al)
end

ae=bit32.bxor(ae,af)
ae=FMix32(ae)

return ae
end

return MurmurHash3 end function a.n():typeof(__modImpl())local aa=a.cache.n if not aa then aa={c=__modImpl()}a.cache.n=aa end return aa.c end end do local function __modImpl()


local aa=table.freeze{
HMAC=a.a(),
KMAC=a.b(),
MD5=a.c(),
SHA1=a.d(),
SHA2=a.i(),
SHA3=a.j(),
XXH32=a.k(),
Blake2b=a.l(),
Blake3=a.m(),
MurMur=a.n()
}

return aa end function a.o():typeof(__modImpl())local aa=a.cache.o if not aa then aa={c=__modImpl()}a.cache.o=aa end return aa.c end end do local function __modImpl()






















local aa=table.create(256)::{number}
for ab=0,255 do
local ac=ab
for ad=1,8 do
if bit32.band(ac,1)==1 then
ac=bit32.bxor(bit32.rshift(ac,1),0xEDB88320)
else
ac=bit32.rshift(ac,1)
end
end

aa[ab+1]=ac
end

local function CRC32(ab:buffer,ac:"Jam"|"Iso"?,ad:boolean?):number|string
local ae=aa
local af=0xFFFFFFFF

local ag=buffer.len(ab)%4

for ah=0,ag-1 do
local ai=buffer.readu8(ab,ah)
local aj=bit32.band(bit32.bxor(af,ai),0xFF)+1

af=bit32.bxor(
ae[aj],
bit32.rshift(af,8)
)
end

for ah=ag,buffer.len(ab)-1,4 do
local ai=bit32.band(bit32.bxor(af,buffer.readu8(ab,ah)),0xFF)+1
af=bit32.bxor(ae[ai],bit32.rshift(af,8))

ai=bit32.band(bit32.bxor(af,buffer.readu8(ab,ah+1)),0xFF)+1
af=bit32.bxor(ae[ai],bit32.rshift(af,8))

ai=bit32.band(bit32.bxor(af,buffer.readu8(ab,ah+2)),0xFF)+1
af=bit32.bxor(ae[ai],bit32.rshift(af,8))

ai=bit32.band(bit32.bxor(af,buffer.readu8(ab,ah+3)),0xFF)+1
af=bit32.bxor(ae[ai],bit32.rshift(af,8))
end

if ac=="Jam"then
return ad==true and string.format("%08x",af)or af
end

af=bit32.bxor(af,0xFFFFFFFF)
return ad==true and string.format("%08x",af)or af
end

return CRC32 end function a.p():typeof(__modImpl())local aa=a.cache.p if not aa then aa={c=__modImpl()}a.cache.p=aa end return aa.c end end do local function __modImpl()













local function Adler(aa:buffer):number
local ab=65522

local ac=bit32.band(bit32.rshift(ab,16),0xffff)
ab=bit32.band(ab,0xffff)

local ad=buffer.len(aa)

if ad==1 then
ab+=buffer.readu8(aa,0)
if ab>=65521 then
ab-=65521
end

ac+=ab
if ac>=65521 then
ac-=65521
end

return bit32.bor(ab,bit32.lshift(ac,16))
end

if ad==0 then
return 0x1
end

local ae=0

if ad<16 then
while ad>0 do
local af=buffer.readu8(aa,ae)

ab+=af
ac+=ab

ae+=1
ad-=1
end

if ab>=65521 then
ab-=65521
end
ac%=65521

return bit32.bor(ab,bit32.lshift(ac,16))
end

local af=5552
while ad>=af do
ad-=af

local ag=af/16
while ag>0 do
ag-=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1
end
end

if ad>0 then
while ad>=16 do
ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1

ad-=16
end

while ad>0 do
ab+=buffer.readu8(aa,ae)
ac+=ab
ae+=1
ad-=1
end

ab%=65521
ac%=65521
end

return bit32.bor(ab,bit32.lshift(ac,16))
end

return Adler end function a.q():typeof(__modImpl())local aa=a.cache.q if not aa then aa={c=__modImpl()}a.cache.q=aa end return aa.c end end do local function __modImpl()


local aa=table.freeze{
CRC32=a.p(),
Adler=a.q()
}

return aa end function a.r():typeof(__modImpl())local aa=a.cache.r if not aa then aa={c=__modImpl()}a.cache.r=aa end return aa.c end end do local function __modImpl()















local function RandomString(aa:number,ab:boolean?):string|buffer
local ac=buffer.create(aa)

for ad=0,aa-1 do
buffer.writeu8(ac,ad,math.random(36,122))
end

return if ab
then ac
else buffer.tostring(ac)
end

return RandomString end function a.s():typeof(__modImpl())local aa=a.cache.s if not aa then aa={c=__modImpl()}a.cache.s=aa end return aa.c end end do local function __modImpl()













local aa=buffer.create(512)do
local ab="0123456789abcdef"
for ac=0,255 do
local ad=bit32.rshift(ac,4)
local ae=ac%16

local af=string.byte(ab,ad+1)
local ag=string.byte(ab,ae+1)

local ah=af+bit32.lshift(ag,8)
buffer.writeu16(aa,ac*2,ah)
end
end

local ab=buffer.create(131072)do
for ac=0,255 do
for ad=0,255 do
local ae=0
local af=0

if ac>=48 and ac<=57 then
ae=ac-48
elseif ac>=65 and ac<=70 then
ae=ac-55
elseif ac>=97 and ac<=102 then
ae=ac-87
else
ae=0
end

if ad>=48 and ad<=57 then
af=ad-48
elseif ad>=65 and ad<=70 then
af=ad-55
elseif ad>=97 and ad<=102 then
af=ad-87
else
af=0
end

local ag=bit32.lshift(ae,4)+af
local ah=bit32.lshift(ad,8)+ac
buffer.writeu16(ab,ah*2,ag)
end
end
end

local ac={}

function ac.ToHex(ad:buffer):string
local ae=buffer.len(ad)
local af=buffer.create(ae*2)

local ag=aa

local ah=ae%8
local ai=0

for aj=0,ae-ah-1,8 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
local al=buffer.readu16(ag,buffer.readu8(ad,aj+1)*2)
local am=buffer.readu16(ag,buffer.readu8(ad,aj+2)*2)
local an=buffer.readu16(ag,buffer.readu8(ad,aj+3)*2)
local ao=buffer.readu16(ag,buffer.readu8(ad,aj+4)*2)
local ap=buffer.readu16(ag,buffer.readu8(ad,aj+5)*2)
local aq=buffer.readu16(ag,buffer.readu8(ad,aj+6)*2)
local ar=buffer.readu16(ag,buffer.readu8(ad,aj+7)*2)

buffer.writeu16(af,ai,ak)
buffer.writeu16(af,ai+2,al)
buffer.writeu16(af,ai+4,am)
buffer.writeu16(af,ai+6,an)
buffer.writeu16(af,ai+8,ao)
buffer.writeu16(af,ai+10,ap)
buffer.writeu16(af,ai+12,aq)
buffer.writeu16(af,ai+14,ar)

ai+=16
end

for aj=ae-ah,ae-1 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
buffer.writeu16(af,ai,ak)
ai+=2
end

return buffer.tostring(af)
end

function ac.FromHex(ad:string|buffer):buffer
local ae=if type(ad)=="string"then buffer.fromstring(ad)else ad
local af=buffer.len(ae)
if af%2~=0 then
error(`Length must be even, got {af}`)
end

local ag=buffer.create(bit32.rshift(af,1))
local ah=af%16
local ai=0
local aj=ab

for ak=0,af-ah-1,16 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(ae,ak+2)
local an=buffer.readu16(ae,ak+4)
local ao=buffer.readu16(ae,ak+6)
local ap=buffer.readu16(ae,ak+8)
local aq=buffer.readu16(ae,ak+10)
local ar=buffer.readu16(ae,ak+12)
local as=buffer.readu16(ae,ak+14)

local at=buffer.readu16(aj,al*2)
local au=buffer.readu16(aj,am*2)
local av=buffer.readu16(aj,an*2)
local aw=buffer.readu16(aj,ao*2)
local ax=buffer.readu16(aj,ap*2)
local ay=buffer.readu16(aj,aq*2)
local az=buffer.readu16(aj,ar*2)
local aA=buffer.readu16(aj,as*2)

local aB=bit32.lshift(aw,24)+bit32.lshift(av,16)+
bit32.lshift(au,8)+at
local aC=bit32.lshift(aA,24)+bit32.lshift(az,16)+
bit32.lshift(ay,8)+ax

buffer.writeu32(ag,ai,aB)
buffer.writeu32(ag,ai+4,aC)
ai+=8
end

for ak=af-ah,af-1,2 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(aj,al*2)
buffer.writeu8(ag,ai,am)
ai+=1
end

return ag
end

return ac end function a.t():typeof(__modImpl())local aa=a.cache.t if not aa then aa={c=__modImpl()}a.cache.t=aa end return aa.c end end do local function __modImpl()














local aa=61
local ab=buffer.create(64)do
local ac={
65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,
81,82,83,84,85,86,87,88,89,90,
97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,
113,114,115,116,117,118,119,120,121,122,
48,49,50,51,52,53,54,55,56,57,
43,47
}

for ad=1,64 do
buffer.writeu8(ab,ad-1,ac[ad])
end
end

local ac,ad=buffer.create(131072),buffer.create(131072)do
for ae=0,255 do
local af=ae//4
local ag=buffer.readu8(ab,af)
local ah=ae%4
for ai=0,255 do
local aj=ah*16+(ai//16)
local ak=(ae+ai*256)*2
buffer.writeu16(ac,ak,ag+buffer.readu8(ab,aj)*256)
end
end

for ae=0,255 do
local af=(ae%16)*4
for ag=0,255 do
local ah=af+(ag//64)
local ai=ag%64
local aj=(ae+ag*256)*2
buffer.writeu16(ad,aj,buffer.readu8(ab,ah)+buffer.readu8(ab,ai)*256)
end
end
end

local ae=buffer.create(256)do
for af=1,64 do
buffer.writeu8(ae,buffer.readu8(ab,af-1),af-1)
end

buffer.writeu8(ae,aa,254)
end

local af=buffer.create(131072)do
for ag=0,255 do
local ah=buffer.readu8(ae,ag)
for ai=0,255 do
local aj=buffer.readu8(ae,ai)
local ak=(ag+ai*256)*2
if ah<64 and aj<64 then
buffer.writeu16(af,ak,ah*64+aj)
elseif ah==254 or aj==254 then
buffer.writeu16(af,ak,254)
end
end
end
end

local ag=buffer.create(4096)
local ah=buffer.create(4096)

local ai,aj=buffer.create(4096),buffer.create(4096)do
for ak=0,4095 do
local al=ak//64
local am=ak%64
buffer.writeu8(ai,ak,al*4+(am//16))
buffer.writeu8(ag,ak,(am%16)*16)
end

for ak=0,4095 do
local al=ak//64
local am=ak%64
buffer.writeu8(ah,ak,al//4)
buffer.writeu8(aj,ak,(al%4)*64+am)
end
end

local function Encode(ak:buffer):buffer
local al=buffer.len(ak)
if al==0 then
return buffer.create(0)
end

local am=buffer.create(((al+2)//3)*4)
local an=0
local ao=0
local ap=al-(al%3)
local aq=al-13

local ar=ac
local as=ad
local at=ab

while an<=aq do
local au=buffer.readu32(ak,an)
local av=buffer.readu32(ak,an+3)
local aw=buffer.readu32(ak,an+6)
local ax=buffer.readu32(ak,an+9)

local ay=au%65536
local az=(au//256)%65536
buffer.writeu32(am,ao,buffer.readu16(ar,ay*2)+buffer.readu16(as,az*2)*0x10000)

local aA=av%65536
local aB=(av//256)%65536
buffer.writeu32(am,ao+4,buffer.readu16(ar,aA*2)+buffer.readu16(as,aB*2)*0x10000)

local aC=aw%65536
local aD=(aw//256)%65536
buffer.writeu32(am,ao+8,buffer.readu16(ar,aC*2)+buffer.readu16(as,aD*2)*0x10000)

local aE=ax%65536
local aF=(ax//256)%65536
buffer.writeu32(am,ao+12,buffer.readu16(ar,aE*2)+buffer.readu16(as,aF*2)*0x10000)

an+=12
ao+=16
end

while an<ap do
local au=buffer.readu16(ak,an)
local av=buffer.readu8(ak,an+2)
local aw=(au//256)+av*256
buffer.writeu32(am,ao,buffer.readu16(ar,au*2)+buffer.readu16(as,aw*2)*0x10000)
an+=3
ao+=4
end

local au=al-an
if au==1 then
local av=buffer.readu8(ak,an)
local aw=av//4
local ax=(av%4)*16
local ay=buffer.readu8(at,aw)+buffer.readu8(at,ax)*256
buffer.writeu16(am,ao,ay)
buffer.writeu8(am,ao+2,aa)
buffer.writeu8(am,ao+3,aa)
elseif au==2 then
local av=buffer.readu8(ak,an)
local aw=buffer.readu8(ak,an+1)
local ax=av+aw*256
buffer.writeu16(am,ao,buffer.readu16(ar,ax*2))
local ay=(aw%16)*4
buffer.writeu8(am,ao+2,buffer.readu8(at,ay))
buffer.writeu8(am,ao+3,aa)
end

return am
end

local function Decode(ak:buffer):buffer
local al=buffer.len(ak)
if al==0 then
return buffer.create(0)
end

local am=0
if buffer.readu8(ak,al-1)==aa then
am=1
if buffer.readu8(ak,al-2)==aa then
am=2
end
end

local an=buffer.create((al//4)*3-am)
local ao=0
local ap=0
local aq=al-4
local ar=aq-8

local as=af
local at=ai
local au=ag
local av=ah
local aw=aj
local ax=ae

while ao<=ar do
local ay=buffer.readu32(ak,ao)
local az=buffer.readu32(ak,ao+4)

local aA=buffer.readu16(as,(ay%65536)*2)
local aB=buffer.readu16(as,(ay//65536)*2)
buffer.writeu8(an,ap,buffer.readu8(at,aA))
buffer.writeu8(an,ap+1,buffer.readu8(au,aA)+buffer.readu8(av,aB))
buffer.writeu8(an,ap+2,buffer.readu8(aw,aB))

local aC=buffer.readu16(as,(az%65536)*2)
local aD=buffer.readu16(as,(az//65536)*2)
buffer.writeu8(an,ap+3,buffer.readu8(at,aC))
buffer.writeu8(an,ap+4,buffer.readu8(au,aC)+buffer.readu8(av,aD))
buffer.writeu8(an,ap+5,buffer.readu8(aw,aD))

ao+=8
ap+=6
end

while ao<=aq-4 do
local ay=buffer.readu32(ak,ao)
local az=buffer.readu16(as,(ay%65536)*2)
local aA=buffer.readu16(as,(ay//65536)*2)
buffer.writeu8(an,ap,buffer.readu8(at,az))
buffer.writeu8(an,ap+1,buffer.readu8(au,az)+buffer.readu8(av,aA))
buffer.writeu8(an,ap+2,buffer.readu8(aw,aA))
ao+=4
ap+=3
end

local ay=buffer.readu8(ak,ao)
local az=buffer.readu8(ak,ao+1)
local aA=buffer.readu8(ak,ao+2)
local aB=buffer.readu8(ak,ao+3)
local aC=buffer.readu8(ax,ay)
local aD=buffer.readu8(ax,az)

if aA==aa then
local aE=aC*64+aD
buffer.writeu8(an,ap,buffer.readu8(at,aE))
elseif aB==aa then
local aE=buffer.readu8(ax,aA)
local aF=aC*64+aD
local aG=aE*64
buffer.writeu8(an,ap,buffer.readu8(at,aF))
buffer.writeu8(an,ap+1,buffer.readu8(au,aF)+(aG//256))
else
local aE=buffer.readu8(ax,aA)
local aF=buffer.readu8(ax,aB)
local aG=aC*64+aD
local aH=aE*64+aF
buffer.writeu8(an,ap,buffer.readu8(at,aG))
buffer.writeu8(an,ap+1,buffer.readu8(au,aG)+buffer.readu8(av,aH))
buffer.writeu8(an,ap+2,buffer.readu8(aw,aH))
end

return an
end

return{
Encode=Encode,
Decode=Decode
}end function a.u():typeof(__modImpl())local aa=a.cache.u if not aa then aa={c=__modImpl()}a.cache.u=aa end return aa.c end end do local function __modImpl()













local aa=buffer.create(512)do
local ab="0123456789abcdef"
for ac=0,255 do
local ad=bit32.rshift(ac,4)
local ae=ac%16

local af=string.byte(ab,ad+1)
local ag=string.byte(ab,ae+1)

local ah=af+bit32.lshift(ag,8)
buffer.writeu16(aa,ac*2,ah)
end
end

local ab=buffer.create(131072)do
for ac=0,255 do
for ad=0,255 do
local ae=0
local af=0

if ac>=48 and ac<=57 then
ae=ac-48
elseif ac>=65 and ac<=70 then
ae=ac-55
elseif ac>=97 and ac<=102 then
ae=ac-87
else
ae=0
end

if ad>=48 and ad<=57 then
af=ad-48
elseif ad>=65 and ad<=70 then
af=ad-55
elseif ad>=97 and ad<=102 then
af=ad-87
else
af=0
end

local ag=bit32.lshift(ae,4)+af
local ah=bit32.lshift(ad,8)+ac
buffer.writeu16(ab,ah*2,ag)
end
end
end

local ac={}

function ac.ToHex(ad:buffer):string
local ae=buffer.len(ad)
local af=buffer.create(ae*2)

local ag=aa

local ah=ae%8
local ai=0

for aj=0,ae-ah-1,8 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
local al=buffer.readu16(ag,buffer.readu8(ad,aj+1)*2)
local am=buffer.readu16(ag,buffer.readu8(ad,aj+2)*2)
local an=buffer.readu16(ag,buffer.readu8(ad,aj+3)*2)
local ao=buffer.readu16(ag,buffer.readu8(ad,aj+4)*2)
local ap=buffer.readu16(ag,buffer.readu8(ad,aj+5)*2)
local aq=buffer.readu16(ag,buffer.readu8(ad,aj+6)*2)
local ar=buffer.readu16(ag,buffer.readu8(ad,aj+7)*2)

buffer.writeu16(af,ai,ak)
buffer.writeu16(af,ai+2,al)
buffer.writeu16(af,ai+4,am)
buffer.writeu16(af,ai+6,an)
buffer.writeu16(af,ai+8,ao)
buffer.writeu16(af,ai+10,ap)
buffer.writeu16(af,ai+12,aq)
buffer.writeu16(af,ai+14,ar)

ai+=16
end

for aj=ae-ah,ae-1 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
buffer.writeu16(af,ai,ak)
ai+=2
end

return buffer.tostring(af)
end

function ac.FromHex(ad:string|buffer):buffer
local ae=if type(ad)=="string"then buffer.fromstring(ad)else ad
local af=buffer.len(ae)
if af%2~=0 then
error(`Length must be even, got {af}`)
end

local ag=buffer.create(bit32.rshift(af,1))
local ah=af%16
local ai=0
local aj=ab

for ak=0,af-ah-1,16 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(ae,ak+2)
local an=buffer.readu16(ae,ak+4)
local ao=buffer.readu16(ae,ak+6)
local ap=buffer.readu16(ae,ak+8)
local aq=buffer.readu16(ae,ak+10)
local ar=buffer.readu16(ae,ak+12)
local as=buffer.readu16(ae,ak+14)

local at=buffer.readu16(aj,al*2)
local au=buffer.readu16(aj,am*2)
local av=buffer.readu16(aj,an*2)
local aw=buffer.readu16(aj,ao*2)
local ax=buffer.readu16(aj,ap*2)
local ay=buffer.readu16(aj,aq*2)
local az=buffer.readu16(aj,ar*2)
local aA=buffer.readu16(aj,as*2)

local aB=bit32.lshift(aw,24)+bit32.lshift(av,16)+
bit32.lshift(au,8)+at
local aC=bit32.lshift(aA,24)+bit32.lshift(az,16)+
bit32.lshift(ay,8)+ax

buffer.writeu32(ag,ai,aB)
buffer.writeu32(ag,ai+4,aC)
ai+=8
end

for ak=af-ah,af-1,2 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(aj,al*2)
buffer.writeu8(ag,ai,am)
ai+=1
end

return ag
end

return ac end function a.v():typeof(__modImpl())local aa=a.cache.v if not aa then aa={c=__modImpl()}a.cache.v=aa end return aa.c end end do local function __modImpl()
























local aa=4
local ab=64
local ac=16

local ad=12
local ae=16
local af=32

local ag=buffer.create(16)do
local ah={string.byte("expand 32-byte k",1,-1)}
for ai,aj in ah do
buffer.writeu8(ag,ai-1,aj)
end
end

local ah=buffer.create(16)do
local ai={string.byte("expand 16-byte k",1,-1)}
for aj,ak in ai do
buffer.writeu8(ah,aj-1,ak)
end
end

local function ProcessBlock(ai:buffer,aj:number)
local ak:number,al:number,am:number,an:number,ao:number,ap:number,aq:number,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number=
buffer.readu32(ai,0),buffer.readu32(ai,4),
buffer.readu32(ai,8),buffer.readu32(ai,12),
buffer.readu32(ai,16),buffer.readu32(ai,20),
buffer.readu32(ai,24),buffer.readu32(ai,28),
buffer.readu32(ai,32),buffer.readu32(ai,36),
buffer.readu32(ai,40),buffer.readu32(ai,44),
buffer.readu32(ai,48),buffer.readu32(ai,52),
buffer.readu32(ai,56),buffer.readu32(ai,60)

for aA=1,aj do
local aB=aA%2==1

if aB then
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),16)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),12)
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),8)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),7)

al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),16)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),12)
al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),8)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),7)

am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),16)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),12)
am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),8)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),7)

an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),16)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),12)
an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),8)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),7)
else
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),16)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),12)
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),8)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),7)

al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),16)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),12)
al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),8)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),7)

am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),16)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),12)
am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),8)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),7)

an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),16)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),12)
an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),8)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),7)
end
end

buffer.writeu32(ai,0,buffer.readu32(ai,0)+ak)
buffer.writeu32(ai,4,buffer.readu32(ai,4)+al)
buffer.writeu32(ai,8,buffer.readu32(ai,8)+am)
buffer.writeu32(ai,12,buffer.readu32(ai,12)+an)
buffer.writeu32(ai,16,buffer.readu32(ai,16)+ao)
buffer.writeu32(ai,20,buffer.readu32(ai,20)+ap)
buffer.writeu32(ai,24,buffer.readu32(ai,24)+aq)
buffer.writeu32(ai,28,buffer.readu32(ai,28)+ar)
buffer.writeu32(ai,32,buffer.readu32(ai,32)+as)
buffer.writeu32(ai,36,buffer.readu32(ai,36)+at)
buffer.writeu32(ai,40,buffer.readu32(ai,40)+au)
buffer.writeu32(ai,44,buffer.readu32(ai,44)+av)
buffer.writeu32(ai,48,buffer.readu32(ai,48)+aw)
buffer.writeu32(ai,52,buffer.readu32(ai,52)+ax)
buffer.writeu32(ai,56,buffer.readu32(ai,56)+ay)
buffer.writeu32(ai,60,buffer.readu32(ai,60)+az)
end

local function InitializeState(ai:buffer,aj:buffer,ak:number):buffer
local al=buffer.len(ai)
local am=buffer.create(ac*aa)

local an=al==32 and ag or ah

buffer.copy(am,0,an,0,16)

buffer.copy(am,16,ai,0,math.min(al,16))
if al==32 then
buffer.copy(am,32,ai,16,16)
else
buffer.copy(am,32,ai,0,16)
end

buffer.writeu32(am,48,ak)
buffer.copy(am,52,aj,0,12)

return am
end

local function ChaCha20(ai:buffer,aj:buffer,ak:buffer,al:number?,am:number?):buffer
if ai==nil then
error("Data cannot be nil",2)
end

if typeof(ai)~="buffer"then
error(`Data must be a buffer, got {typeof(ai)}`,2)
end

if aj==nil then
error("Key cannot be nil",2)
end

if typeof(aj)~="buffer"then
error(`Key must be a buffer, got {typeof(aj)}`,2)
end

local an=buffer.len(aj)
if an~=ae and an~=af then
error(`Key must be {ae} or {af} bytes long, got {an} bytes`,2)
end

if ak==nil then
error("Nonce cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Nonce must be a buffer, got {typeof(ak)}`,2)
end

local ao=buffer.len(ak)
if ao~=ad then
error(`Nonce must be exactly {ad} bytes long, got {ao} bytes`,2)
end

if al then
if typeof(al)~="number"then
error(`Counter must be a number, got {typeof(al)}`,2)
end

if al<0 then
error(`Counter cannot be negative, got {al}`,2)
end

if al~=math.floor(al)then
error(`Counter must be an integer, got {al}`,2)
end

if al>=4294967296 then
error(`Counter must be less than 2^32, got {al}`,2)
end
end

if am then
if typeof(am)~="number"then
error(`Rounds must be a number, got {typeof(am)}`,2)
end

if am<=0 then
error(`Rounds must be positive, got {am}`,2)
end

if am~=math.floor(am)then
error(`Rounds must be an integer, got {am}`,2)
end

if am%2~=0 then
error(`Rounds must be even, got {am}`,2)
end
end

local ap=al or 1
local aq=am or 20

local ar=buffer.len(ai)
if ar==0 then
return buffer.create(0)
end

local as=buffer.create(ar)

local at=0

local au=InitializeState(aj,ak,ap)
local av=buffer.create(64)
buffer.copy(av,0,au,0)

while at<ar do
ProcessBlock(au,aq)

local aw=math.min(ab,ar-at)

for ax=0,aw-1 do
local ay=buffer.readu8(ai,at+ax)
local az=buffer.readu8(au,ax)
buffer.writeu8(as,at+ax,bit32.bxor(ay,az))
end

at+=aw
ap+=1
buffer.copy(au,0,av,0)
buffer.writeu32(au,48,ap)
end

return as
end

return ChaCha20 end function a.w():typeof(__modImpl())local aa=a.cache.w if not aa then aa={c=__modImpl()}a.cache.w=aa end return aa.c end end do local function __modImpl()




























local aa=64
local ab=32
local ac=64
local ad=64
local ae=ad*ab

local af=0x01
local ag=0x02
local ah=0x04
local ai=0x08

local aj=buffer.create(ab)do
local ak={
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
}
for al,am in ipairs(ak)do
buffer.writeu32(aj,(al-1)*4,am)
end
end

local function Compress(ak:buffer,al:buffer,am:number,an:number,ao:number,ap:boolean?):buffer
local aq=buffer.readu32(ak,0)
local ar=buffer.readu32(ak,4)
local as=buffer.readu32(ak,8)
local at=buffer.readu32(ak,12)
local au=buffer.readu32(ak,16)
local av=buffer.readu32(ak,20)
local aw=buffer.readu32(ak,24)
local ax=buffer.readu32(ak,28)

local ay,az,aA,aB=aq,ar,as,at
local aC,aD,aE,aF=au,av,aw,ax
local aG,aH,aI,aJ=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a

local aK=am%(4294967296)
local aL=(am-aK)*(2.3283064365386963E-10)

local b=buffer.readu32(al,0)
local c=buffer.readu32(al,4)
local d=buffer.readu32(al,8)
local e=buffer.readu32(al,12)
local f=buffer.readu32(al,16)
local g=buffer.readu32(al,20)
local h=buffer.readu32(al,24)
local i=buffer.readu32(al,28)
local j=buffer.readu32(al,32)
local k=buffer.readu32(al,36)
local l=buffer.readu32(al,40)
local m=buffer.readu32(al,44)
local n=buffer.readu32(al,48)
local o=buffer.readu32(al,52)
local p=buffer.readu32(al,56)
local q=buffer.readu32(al,60)

local r=bit32.bxor
local s=bit32.lrotate

local t
for u=1,7 do
ay+=aC+b;aK=s(r(aK,ay),16)
aG+=aK;aC=s(r(aC,aG),20)
ay+=aC+c;aK=s(r(aK,ay),24)
aG+=aK;aC=s(r(aC,aG),25)

az+=aD+d;aL=s(r(aL,az),16)
aH+=aL;aD=s(r(aD,aH),20)
az+=aD+e;aL=s(r(aL,az),24)
aH+=aL;aD=s(r(aD,aH),25)

aA+=aE+f;an=s(r(an,aA),16)
aI+=an;aE=s(r(aE,aI),20)
aA+=aE+g;an=s(r(an,aA),24)
aI+=an;aE=s(r(aE,aI),25)

aB+=aF+h;ao=s(r(ao,aB),16)
aJ+=ao;aF=s(r(aF,aJ),20)
aB+=aF+i;ao=s(r(ao,aB),24)
aJ+=ao;aF=s(r(aF,aJ),25)

ay+=aD+j;ao=s(r(ao,ay),16)
aI+=ao;aD=s(r(aD,aI),20)
ay+=aD+k;ao=s(r(ao,ay),24)
aI+=ao;aD=s(r(aD,aI),25)

az+=aE+l;aK=s(r(aK,az),16)
aJ+=aK;aE=s(r(aE,aJ),20)
az+=aE+m;aK=s(r(aK,az),24)
aJ+=aK;aE=s(r(aE,aJ),25)

aA+=aF+n;aL=s(r(aL,aA),16)
aG+=aL;aF=s(r(aF,aG),20)
aA+=aF+o;aL=s(r(aL,aA),24)
aG+=aL;aF=s(r(aF,aG),25)

aB+=aC+p;an=s(r(an,aB),16)
aH+=an;aC=s(r(aC,aH),20)
aB+=aC+q;an=s(r(an,aB),24)
aH+=an;aC=s(r(aC,aH),25)

if u~=7 then
t=d
d=e
e=l
l=n
n=k
k=m
m=g
g=b
b=t

t=h
h=f
f=i
i=o
o=p
p=q
q=j
j=c
c=t
end
end

if ap then
local u=buffer.create(ac)
buffer.writeu32(u,0,r(ay,aG))
buffer.writeu32(u,4,r(az,aH))
buffer.writeu32(u,8,r(aA,aI))
buffer.writeu32(u,12,r(aB,aJ))
buffer.writeu32(u,16,r(aC,aK))
buffer.writeu32(u,20,r(aD,aL))
buffer.writeu32(u,24,r(aE,an))
buffer.writeu32(u,28,r(aF,ao))

buffer.writeu32(u,32,r(aG,aq))
buffer.writeu32(u,36,r(aH,ar))
buffer.writeu32(u,40,r(aI,as))
buffer.writeu32(u,44,r(aJ,at))
buffer.writeu32(u,48,r(aK,au))
buffer.writeu32(u,52,r(aL,av))
buffer.writeu32(u,56,r(an,aw))
buffer.writeu32(u,60,r(ao,ax))

return u
else
local u=buffer.create(ab)
buffer.writeu32(u,0,r(ay,aG))
buffer.writeu32(u,4,r(az,aH))
buffer.writeu32(u,8,r(aA,aI))
buffer.writeu32(u,12,r(aB,aJ))
buffer.writeu32(u,16,r(aC,aK))
buffer.writeu32(u,20,r(aD,aL))
buffer.writeu32(u,24,r(aE,an))
buffer.writeu32(u,28,r(aF,ao))

return u
end
end

local function ProcessMessage(ak:buffer,al:number,am:buffer,an:number):buffer
local ao=buffer.len(am)
local ap=buffer.create(ae)
local aq=0
local ar=buffer.create(ab)
buffer.copy(ar,0,ak,0,ab)

local as=0
local at=0
local au=0
local av=af

local aw=buffer.create(aa)

for ax=0,ao-aa-1,aa do
buffer.copy(aw,0,am,ax,aa)
local ay=al+av+au

ar=Compress(ar,aw,as,aa,ay)
av=0
at+=1

if at==15 then
au=ag
elseif at==16 then
local az=ar
local aA=as+1

while aA%2==0 do
aq=aq-1
local aB=buffer.create(ab)
buffer.copy(aB,0,ap,aq*ab,ab)

local aC=buffer.create(ac)
buffer.copy(aC,0,aB,0,ab)
buffer.copy(aC,ab,az,0,ab)

az=Compress(ak,aC,0,aa,al+ah)
aA=aA/2
end

buffer.copy(ap,aq*ab,az,0,ab)
aq=aq+1
buffer.copy(ar,0,ak,0,ab)
av=af

as+=1
at=0
au=0
end
end

local ax=ao==0 and 0 or((ao-1)%aa+1)
local ay=buffer.create(aa)

if ax>0 then
buffer.copy(ay,0,am,ao-ax,ax)
end

local az:buffer
local aA:buffer
local aB:number
local aC:number

if as>0 then
local aD=al+av+ag
local aE=Compress(ar,ay,as,ax,aD)

for aF=aq,2,-1 do
local aG=buffer.create(ab)
buffer.copy(aG,0,ap,(aF-1)*ab,ab)

local aH=buffer.create(ac)
buffer.copy(aH,0,aG,0,ab)
buffer.copy(aH,ab,aE,0,ab)

aE=Compress(ak,aH,0,aa,al+ah)
end

az=ak
local aF=buffer.create(ab)
buffer.copy(aF,0,ap,0,ab)

aA=buffer.create(ac)
buffer.copy(aA,0,aF,0,ab)
buffer.copy(aA,ab,aE,0,ab)

aB=aa
aC=al+ai+ah
else
az=ar
aA=ay
aB=ax
aC=al+av+ag+ai
end

local aD=buffer.create(an)
local aE=0

for aF=0,an//aa do
local aG=Compress(az,aA,aF,aB,aC,true)

local aH=math.min(aa,an-aE)
buffer.copy(aD,aE,aG,0,aH)
aE+=aH

if aE>=an then
break
end
end

return aD
end

return function(ak:buffer,al:number?):buffer
return ProcessMessage(aj,0,ak,al or 32)
end end function a.x():typeof(__modImpl())local aa=a.cache.x if not aa then aa={c=__modImpl()}a.cache.x=aa end return aa.c end end do local function __modImpl()


























local aa=a.v()
local ab=a.w()
local ac=a.x()


































local ad=64
local ae=32
local af=12

local ag:CSPRNGModule__DARKLUA_TYPE_c={
BlockExpansion=true,
SizeTarget=2048,
RekeyAfter=1024,

Key=buffer.create(0),
Nonce=buffer.create(0),
Buffer=buffer.create(0),

Counter=0,
BufferPosition=0,
BufferSize=0,
BytesLeft=0,

EntropyProviders={}
}::CSPRNGModule__DARKLUA_TYPE_c

local ah=buffer.create(ad)
local ai=math.max(math.floor(ag.RekeyAfter),2)
local aj=math.clamp(math.floor(ag.SizeTarget),64,4294967295)

local function Reset()
ag.Key=buffer.create(0)
ag.Nonce=buffer.create(0)
ag.Buffer=buffer.create(0)

ag.Counter=0
ag.BufferPosition=0
ag.BufferSize=0
end

local function GatherEntropy(ak:buffer?):number
local al=buffer.create(1024)
local am=0

local function WriteToBuffer(an:buffer)
local ao=buffer.len(an)
buffer.copy(al,am,an,0,ao)
am+=ao
end

local an=1.234
if tick then
an=tick()
local ao=buffer.create(8)
buffer.writef64(ao,0,an)
WriteToBuffer(ao)
end

local ao=os.clock()
local ap=buffer.create(8)
buffer.writef64(ap,0,ao)
WriteToBuffer(ap)

local aq=os.time()
local ar=buffer.create(8)
buffer.writeu32(ar,0,aq%0x100000000)
buffer.writeu32(ar,4,math.floor(aq/0x100000000))
WriteToBuffer(ar)

local as=5.678
if DateTime then
as=DateTime.now().UnixTimestampMillis
local at=buffer.create(8)
buffer.writef64(at,0,as)
WriteToBuffer(at)

local au=buffer.create(16)
buffer.writef32(au,0,as/1000)
buffer.writef32(au,4,(as%1000)/100)
buffer.writef32(au,8,as/86400000)
buffer.writef32(au,12,(as*0.001)%1)
WriteToBuffer(au)
else
WriteToBuffer(buffer.create(24))
end

local at=buffer.create(16)
buffer.writef32(at,0,ao/100)
buffer.writef32(at,4,an/1000)
buffer.writef32(at,8,(ao*12345.6789)%1)
buffer.writef32(at,12,(an*98765.4321)%1)
WriteToBuffer(at)

local au=buffer.create(32)
for av=0,7 do
local aw=math.noise(ao+av,aq+av,ao+aq+av)
local ax=math.noise(an+av*0.1,as*0.0001+av,ao*1.5+av)
local ay=math.noise(aq*0.01+av,ao+as*0.001,an+av*2)
local az=math.noise(as*0.00001+av,aq+ao+av,an*0.1+av)

buffer.writef32(au,av*4,aw+ax+ay+az)
end
WriteToBuffer(au)

local av=buffer.create(32)
for aw=0,7 do
local ax=os.clock()
local ay=0

local az=50+(aw*25)
for aA=1,az do
ay+=aA*aA+math.sin(aA/10)*math.cos(aA/7)
end

local aA=os.clock()
local aB=aA-ax
buffer.writef32(av,aw*4,aB*1000000)
end
WriteToBuffer(av)

local aw=buffer.create(24)
for ax=0,5 do
local ay=os.clock()

for az=1,20 do
buffer.create(64+az)
end

local az=os.clock()
buffer.writef32(aw,ax*4,(az-ay)*10000000)
end
WriteToBuffer(aw)

local ax=math.floor(an*1000000)
local ay=buffer.create(8)
buffer.writeu32(ay,0,ax%0x100000000)
buffer.writeu32(ay,4,math.floor(ax/0x100000000))
WriteToBuffer(ay)

if game then
if game.JobId and#game.JobId>0 then
local az=buffer.fromstring(game.JobId)
WriteToBuffer(az)
end

if game.PlaceId then
local az=buffer.create(8)
buffer.writeu32(az,0,game.PlaceId%0x100000000)
buffer.writeu32(az,4,math.floor(game.PlaceId/0x100000000))
WriteToBuffer(az)
end

if workspace and workspace.DistributedGameTime then
local az=buffer.create(8)
buffer.writef64(az,0,workspace.DistributedGameTime)
WriteToBuffer(az)

local aA=math.floor(workspace.DistributedGameTime*1000000)
local aB=buffer.create(8)
buffer.writeu32(aB,0,aA%0x100000000)
buffer.writeu32(aB,4,math.floor(aA/0x100000000))
WriteToBuffer(aB)
end
end

local az=buffer.create(128)
for aA=0,7 do
local aB={}
local aC=function()end
local aD=buffer.create(0)
local aE=newproxy()

local aF=string.gsub(tostring(aB),"table: ","")
local aG=string.gsub(tostring(aC),"function: ","")
local aH=string.gsub(tostring(aD),"buffer: ","")
local aI=string.gsub(tostring(aE),"userdata: ","")

local aJ=0
local aK=0
local aL=0
local b=0
local c=0

for d=1,#aF do
aJ=bit32.bxor(aJ,string.byte(aF,d))*31
end

if coroutine then
local d=string.gsub(tostring(coroutine.create(function()end)),"thread: ","")
for e=1,#d do
aK=bit32.bxor(aK,string.byte(d,e))*31
end
end

for d=1,#aG do
aL=bit32.bxor(aL,string.byte(aG,d))*37
end
for d=1,#aH do
b=bit32.bxor(b,string.byte(aH,d))*41
end
for d=1,#aI do
c=bit32.bxor(c,string.byte(aI,d))*43
end

buffer.writeu32(az,aA*16,aJ)
buffer.writeu32(az,aA*16+4,aK)
buffer.writeu32(az,aA*16+8,aL)
buffer.writeu32(az,aA*16+12,bit32.bxor(b,c))
end
WriteToBuffer(az)

local function AddExtraEntropy(aA:buffer?,aB:boolean,aC:string?)
if not aA then
return
end

local aD=1024-am

if aD>0 then
local aE=buffer.len(aA)-aD
local aF=math.min(aD,buffer.len(aA))

if aE>0 and aB and aC then
warn(`CSPRNG: {aC} returned {aE} bytes more than available and was truncated to {aF} bytes`)
end

buffer.copy(al,am,aA,0,aF)
end
end

for aA,aB in ag.EntropyProviders do
local aC=1024-am
if aC>0 then
local aD:boolean,aE:buffer?=pcall(aB,aC)
if not aD then
warn(`CSPRNG Provider errored with {aE}`)
end

AddExtraEntropy(aE,true,`Entropy Provider #{aA}`)
end
end

if ak then
AddExtraEntropy(ak,false)
end

local aA=ac(al,ae+af)

ag.Key=buffer.create(ae)
buffer.copy(ag.Key,0,aA,0,ae)

ag.Nonce=buffer.create(af)
buffer.copy(ag.Nonce,0,aA,ae,af)

return buffer.len(al)-am
end

local function GenerateBlock()
buffer.fill(ah,0,0,ad)
local ak=ab(ah,ag.Key,ag.Nonce,ag.Counter,20)

ag.Buffer=if ag.BlockExpansion then ac(ak,aj)else ak
ag.BufferPosition=0
ag.BufferSize=buffer.len(ag.Buffer)
ag.Counter+=1

if ag.Counter%ai==0 then
GatherEntropy()
ag.Counter=0
end
end

local function GetBytes(ak:number):buffer
local al=buffer.create(ak)
local am=0

while am<ak do
if ag.BufferPosition>=ag.BufferSize then
GenerateBlock()
end

local an=ak-am
local ao=ag.BufferSize-ag.BufferPosition
local ap=math.min(an,ao)

buffer.copy(al,am,ag.Buffer,ag.BufferPosition,ap)
am+=ap
ag.BufferPosition+=ap
end

return al
end

local function GetFloat():number
if ag.BufferPosition+8>ag.BufferSize then
GenerateBlock()
end

local ak=buffer.readu32(ag.Buffer,ag.BufferPosition)
local al=buffer.readu32(ag.Buffer,ag.BufferPosition+4)
ag.BufferPosition+=8

local am=bit32.rshift(ak,5)
local an=bit32.rshift(al,6)

return(am*67108864.0+an)/9007199254740992.0
end

local function GetIntRange(ak:number,al:number):number
local am=al-ak+1
local an=0xFFFFFFFF
local ao=an-(an%am)

if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end

local ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4

if bit32.band(am,am-1)==0 then
return ak+bit32.band(ap,am-1)
else
while ap>ao do
if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end
ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4
end

return ak+(ap%am)
end
end

local function GetNumberRange(ak:number,al:number):number
if ak>al then
ak,al=al,ak
end

local am=al-ak
if am<=0 then
return ak
end

return ak+(GetFloat()*am)
end

local function GetRandomString(ak:number,al:boolean?):string|buffer
local am=buffer.create(ak)

for an=0,ak-1 do
buffer.writeu8(am,an,GetIntRange(36,122))
end

return if al
then am
else buffer.tostring(am)
end

local function GetEd25519RandomBytes():buffer
local ak=buffer.create(32)

for al=0,31 do
buffer.writeu8(ak,al,GetIntRange(0,255))
end

return ak
end

local function GetEd25519ClampedBytes(ak:buffer):buffer
local al=buffer.create(32)
buffer.copy(al,0,ak,0,32)

local am=buffer.readu8(al,0)
am=bit32.band(am,0xF8)
buffer.writeu8(al,0,am)

local an=buffer.readu8(al,31)
an=bit32.band(an,0x7F)
an=bit32.bor(an,0x40)
buffer.writeu8(al,31,an)

local ao=false
local ap=buffer.readu8(al,1)
for aq=2,30 do
if buffer.readu8(al,aq)~=ap then
ao=true
break
end
end

if not ao then
buffer.writeu8(al,15,bit32.bxor(ap,0x55))
end

return al
end

local function GetHexString(ak:number):string
local al=ak/2
local am=GetBytes(al)
local an=aa.ToHex(am)

return an
end

function ag.AddEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_b)
table.insert(ag.EntropyProviders,ak)
end

function ag.RemoveEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_b)
for al=#ag.EntropyProviders,1,-1 do
if ag.EntropyProviders[al]==ak then
table.remove(ag.EntropyProviders,al)
break
end
end
end

function ag.Random():number
return GetFloat()
end

function ag.RandomInt(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) can't be less than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=1
else
am=al
an=ak
end

return GetIntRange(an,am)
end

function ag.RandomNumber(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) must be bigger than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=0
else
am=al
an=ak
end

return GetNumberRange(an,am)
end

function ag.RandomBytes(ak:number):buffer
if type(ak)~="number"then
error(`Count must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Count must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Count must be an integer",2)
end

return GetBytes(ak)
end

function ag.RandomString(ak:number,al:boolean?):string|buffer
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if al~=nil and type(al)~="boolean"then
error(`AsBuffer must be a boolean or nil, got {typeof(al)}`,2)
end

return GetRandomString(ak,al)
end

function ag.RandomHex(ak:number):string
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if ak%2~=0 then
error(`Length must be even, got {ak}`,2)
end

return GetHexString(ak)
end

function ag.Ed25519ClampedBytes(ak:buffer):buffer
if type(ak)~="buffer"then
error(`Input must be a buffer, got {typeof(ak)}`,2)
end

return GetEd25519ClampedBytes(ak)
end

function ag.Ed25519Random():buffer
return GetEd25519ClampedBytes(GetEd25519RandomBytes())
end

function ag.Reseed(ak:buffer?)
if ak~=nil and type(ak)~="buffer"then
error(`CustomEntropy must be a buffer or nil, got {typeof(ak)}`,2)
end

Reset()
GatherEntropy(ak)
end

ag.BytesLeft=GatherEntropy()
GenerateBlock()

return ag end function a.y():typeof(__modImpl())local aa=a.cache.y if not aa then aa={c=__modImpl()}a.cache.y=aa end return aa.c end end do local function __modImpl()


local aa=table.freeze{
RandomString=a.s(),
Conversions=a.t(),
Base64=a.u(),
CSPRNG=a.y()
}

return aa end function a.z():typeof(__modImpl())local aa=a.cache.z if not aa then aa={c=__modImpl()}a.cache.z=aa end return aa.c end end do local function __modImpl()

























local aa={}

local ab=4
local ac=64
local ad=16

local ae=12
local af=24

local ag=16
local ah=32

local ai=buffer.create(16)do
local aj={string.byte("expand 32-byte k",1,-1)}
for ak,al in aj do
buffer.writeu8(ai,ak-1,al)
end
end

local aj=buffer.create(16)do
local ak={string.byte("expand 16-byte k",1,-1)}
for al,am in ak do
buffer.writeu8(aj,al-1,am)
end
end

local function ProcessBlock(ak:buffer,al:number)
local am:number,an:number,ao:number,ap:number,aq:number,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number,aA:number,aB:number=
buffer.readu32(ak,0),buffer.readu32(ak,4),
buffer.readu32(ak,8),buffer.readu32(ak,12),
buffer.readu32(ak,16),buffer.readu32(ak,20),
buffer.readu32(ak,24),buffer.readu32(ak,28),
buffer.readu32(ak,32),buffer.readu32(ak,36),
buffer.readu32(ak,40),buffer.readu32(ak,44),
buffer.readu32(ak,48),buffer.readu32(ak,52),
buffer.readu32(ak,56),buffer.readu32(ak,60)

for aC=1,al do
local aD=aC%2==1

if aD then
am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),16)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),12)
am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),8)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),7)

an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),16)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),12)
an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),8)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),7)

ao=bit32.bor(ao+as,0);aA=bit32.lrotate(bit32.bxor(aA,ao),16)
aw=bit32.bor(aw+aA,0);as=bit32.lrotate(bit32.bxor(as,aw),12)
ao=bit32.bor(ao+as,0);aA=bit32.lrotate(bit32.bxor(aA,ao),8)
aw=bit32.bor(aw+aA,0);as=bit32.lrotate(bit32.bxor(as,aw),7)

ap=bit32.bor(ap+at,0);aB=bit32.lrotate(bit32.bxor(aB,ap),16)
ax=bit32.bor(ax+aB,0);at=bit32.lrotate(bit32.bxor(at,ax),12)
ap=bit32.bor(ap+at,0);aB=bit32.lrotate(bit32.bxor(aB,ap),8)
ax=bit32.bor(ax+aB,0);at=bit32.lrotate(bit32.bxor(at,ax),7)
else
am=bit32.bor(am+ar,0);aB=bit32.lrotate(bit32.bxor(aB,am),16)
aw=bit32.bor(aw+aB,0);ar=bit32.lrotate(bit32.bxor(ar,aw),12)
am=bit32.bor(am+ar,0);aB=bit32.lrotate(bit32.bxor(aB,am),8)
aw=bit32.bor(aw+aB,0);ar=bit32.lrotate(bit32.bxor(ar,aw),7)

an=bit32.bor(an+as,0);ay=bit32.lrotate(bit32.bxor(ay,an),16)
ax=bit32.bor(ax+ay,0);as=bit32.lrotate(bit32.bxor(as,ax),12)
an=bit32.bor(an+as,0);ay=bit32.lrotate(bit32.bxor(ay,an),8)
ax=bit32.bor(ax+ay,0);as=bit32.lrotate(bit32.bxor(as,ax),7)

ao=bit32.bor(ao+at,0);az=bit32.lrotate(bit32.bxor(az,ao),16)
au=bit32.bor(au+az,0);at=bit32.lrotate(bit32.bxor(at,au),12)
ao=bit32.bor(ao+at,0);az=bit32.lrotate(bit32.bxor(az,ao),8)
au=bit32.bor(au+az,0);at=bit32.lrotate(bit32.bxor(at,au),7)

ap=bit32.bor(ap+aq,0);aA=bit32.lrotate(bit32.bxor(aA,ap),16)
av=bit32.bor(av+aA,0);aq=bit32.lrotate(bit32.bxor(aq,av),12)
ap=bit32.bor(ap+aq,0);aA=bit32.lrotate(bit32.bxor(aA,ap),8)
av=bit32.bor(av+aA,0);aq=bit32.lrotate(bit32.bxor(aq,av),7)
end
end

buffer.writeu32(ak,0,buffer.readu32(ak,0)+am)
buffer.writeu32(ak,4,buffer.readu32(ak,4)+an)
buffer.writeu32(ak,8,buffer.readu32(ak,8)+ao)
buffer.writeu32(ak,12,buffer.readu32(ak,12)+ap)
buffer.writeu32(ak,16,buffer.readu32(ak,16)+aq)
buffer.writeu32(ak,20,buffer.readu32(ak,20)+ar)
buffer.writeu32(ak,24,buffer.readu32(ak,24)+as)
buffer.writeu32(ak,28,buffer.readu32(ak,28)+at)
buffer.writeu32(ak,32,buffer.readu32(ak,32)+au)
buffer.writeu32(ak,36,buffer.readu32(ak,36)+av)
buffer.writeu32(ak,40,buffer.readu32(ak,40)+aw)
buffer.writeu32(ak,44,buffer.readu32(ak,44)+ax)
buffer.writeu32(ak,48,buffer.readu32(ak,48)+ay)
buffer.writeu32(ak,52,buffer.readu32(ak,52)+az)
buffer.writeu32(ak,56,buffer.readu32(ak,56)+aA)
buffer.writeu32(ak,60,buffer.readu32(ak,60)+aB)
end

local function InitializeState(ak:buffer,al:buffer,am:number):buffer
local an=buffer.len(ak)
local ao=buffer.create(ad*ab)

local ap=an==32 and ai or aj

buffer.copy(ao,0,ap,0,16)

buffer.copy(ao,16,ak,0,math.min(an,16))
if an==32 then
buffer.copy(ao,32,ak,16,16)
else
buffer.copy(ao,32,ak,0,16)
end

buffer.writeu32(ao,48,am)
buffer.copy(ao,52,al,0,12)

return ao
end

function aa.ChaCha20(ak:buffer,al:buffer,am:buffer,an:number?,ao:number?):buffer
if ak==nil then
error("Data cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Data must be a buffer, got {typeof(ak)}`,2)
end

if al==nil then
error("Key cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`Key must be a buffer, got {typeof(al)}`,2)
end

local ap=buffer.len(al)
if ap~=ag and ap~=ah then
error(`Key must be {ag} or {ah} bytes long, got {ap} bytes`,2)
end

if am==nil then
error("Nonce cannot be nil",2)
end

if typeof(am)~="buffer"then
error(`Nonce must be a buffer, got {typeof(am)}`,2)
end

local aq=buffer.len(am)
if aq~=ae then
error(`Nonce must be exactly {ae} bytes long, got {aq} bytes`,2)
end

if an then
if typeof(an)~="number"then
error(`Counter must be a number, got {typeof(an)}`,2)
end

if an<0 then
error(`Counter cannot be negative, got {an}`,2)
end

if an~=math.floor(an)then
error(`Counter must be an integer, got {an}`,2)
end

if an>=4294967296 then
error(`Counter must be less than 2^32, got {an}`,2)
end
end

if ao then
if typeof(ao)~="number"then
error(`Rounds must be a number, got {typeof(ao)}`,2)
end

if ao<=0 then
error(`Rounds must be positive, got {ao}`,2)
end

if ao~=math.floor(ao)then
error(`Rounds must be an integer, got {ao}`,2)
end

if ao%2~=0 then
error(`Rounds must be even, got {ao}`,2)
end
end

local ar=an or 1
local as=ao or 20

local at=buffer.len(ak)
if at==0 then
return buffer.create(0)
end

local au=buffer.create(at)

local av=0

local aw=InitializeState(al,am,ar)
local ax=buffer.create(64)
buffer.copy(ax,0,aw,0)

while av<at do
ProcessBlock(aw,as)

local ay=math.min(ac,at-av)

for az=0,ay-1 do
local aA=buffer.readu8(ak,av+az)
local aB=buffer.readu8(aw,az)
buffer.writeu8(au,av+az,bit32.bxor(aA,aB))
end

av+=ay
ar+=1
buffer.copy(aw,0,ax,0)
buffer.writeu32(aw,48,ar)
end

return au
end

function aa.HChaCha20(ak:buffer,al:buffer,am:number?):buffer
if ak==nil then
error("Key cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Key must be a buffer, got {typeof(ak)}`,2)
end

local an=buffer.len(ak)
if an~=ag and an~=ah then
error(`Key must be {ag} or {ah} bytes long, got {an} bytes`,2)
end

if al==nil then
error("Nonce cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`Nonce must be a buffer, got {typeof(al)}`,2)
end

local ao=buffer.len(al)
if ao~=16 then
error(`HChaCha20 requires a 16-byte nonce, got {ao} bytes`,2)
end

if am then
if typeof(am)~="number"then
error(`Rounds must be a number, got {typeof(am)}`,2)
end

if am<=0 then
error(`Rounds must be positive, got {am}`,2)
end

if am~=math.floor(am)then
error(`Rounds must be an integer, got {am}`,2)
end

if am%2~=0 then
error(`Rounds must be even, got {am}`,2)
end
end

local ap=am or 20

local aq:buffer
if an==ah then
aq=ak
else
aq=buffer.create(32)
buffer.copy(aq,0,ak,0,16)
buffer.copy(aq,16,ak,0,16)
end

local ar=(buffer.len(aq)==32)and ai or aj

local as=buffer.create(ad*ab)
buffer.copy(as,0,ar,0,16)
buffer.copy(as,16,aq,0,16)
buffer.copy(as,32,aq,16,16)
buffer.copy(as,48,al,0,16)

local at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number,aA:number,aB:number,aC:number,aD:number,aE:number,aF:number,aG:number,aH:number,aI:number=
buffer.readu32(as,0),buffer.readu32(as,4),
buffer.readu32(as,8),buffer.readu32(as,12),
buffer.readu32(as,16),buffer.readu32(as,20),
buffer.readu32(as,24),buffer.readu32(as,28),
buffer.readu32(as,32),buffer.readu32(as,36),
buffer.readu32(as,40),buffer.readu32(as,44),
buffer.readu32(as,48),buffer.readu32(as,52),
buffer.readu32(as,56),buffer.readu32(as,60)

for aJ=1,ap do
local aK=aJ%2==1

if aK then
at=bit32.bor(at+ax,0);aF=bit32.lrotate(bit32.bxor(aF,at),16)
aB=bit32.bor(aB+aF,0);ax=bit32.lrotate(bit32.bxor(ax,aB),12)
at=bit32.bor(at+ax,0);aF=bit32.lrotate(bit32.bxor(aF,at),8)
aB=bit32.bor(aB+aF,0);ax=bit32.lrotate(bit32.bxor(ax,aB),7)

au=bit32.bor(au+ay,0);aG=bit32.lrotate(bit32.bxor(aG,au),16)
aC=bit32.bor(aC+aG,0);ay=bit32.lrotate(bit32.bxor(ay,aC),12)
au=bit32.bor(au+ay,0);aG=bit32.lrotate(bit32.bxor(aG,au),8)
aC=bit32.bor(aC+aG,0);ay=bit32.lrotate(bit32.bxor(ay,aC),7)

av=bit32.bor(av+az,0);aH=bit32.lrotate(bit32.bxor(aH,av),16)
aD=bit32.bor(aD+aH,0);az=bit32.lrotate(bit32.bxor(az,aD),12)
av=bit32.bor(av+az,0);aH=bit32.lrotate(bit32.bxor(aH,av),8)
aD=bit32.bor(aD+aH,0);az=bit32.lrotate(bit32.bxor(az,aD),7)

aw=bit32.bor(aw+aA,0);aI=bit32.lrotate(bit32.bxor(aI,aw),16)
aE=bit32.bor(aE+aI,0);aA=bit32.lrotate(bit32.bxor(aA,aE),12)
aw=bit32.bor(aw+aA,0);aI=bit32.lrotate(bit32.bxor(aI,aw),8)
aE=bit32.bor(aE+aI,0);aA=bit32.lrotate(bit32.bxor(aA,aE),7)
else
at=bit32.bor(at+ay,0);aI=bit32.lrotate(bit32.bxor(aI,at),16)
aD=bit32.bor(aD+aI,0);ay=bit32.lrotate(bit32.bxor(ay,aD),12)
at=bit32.bor(at+ay,0);aI=bit32.lrotate(bit32.bxor(aI,at),8)
aD=bit32.bor(aD+aI,0);ay=bit32.lrotate(bit32.bxor(ay,aD),7)

au=bit32.bor(au+az,0);aF=bit32.lrotate(bit32.bxor(aF,au),16)
aE=bit32.bor(aE+aF,0);az=bit32.lrotate(bit32.bxor(az,aE),12)
au=bit32.bor(au+az,0);aF=bit32.lrotate(bit32.bxor(aF,au),8)
aE=bit32.bor(aE+aF,0);az=bit32.lrotate(bit32.bxor(az,aE),7)

av=bit32.bor(av+aA,0);aG=bit32.lrotate(bit32.bxor(aG,av),16)
aB=bit32.bor(aB+aG,0);aA=bit32.lrotate(bit32.bxor(aA,aB),12)
av=bit32.bor(av+aA,0);aG=bit32.lrotate(bit32.bxor(aG,av),8)
aB=bit32.bor(aB+aG,0);aA=bit32.lrotate(bit32.bxor(aA,aB),7)

aw=bit32.bor(aw+ax,0);aH=bit32.lrotate(bit32.bxor(aH,aw),16)
aC=bit32.bor(aC+aH,0);ax=bit32.lrotate(bit32.bxor(ax,aC),12)
aw=bit32.bor(aw+ax,0);aH=bit32.lrotate(bit32.bxor(aH,aw),8)
aC=bit32.bor(aC+aH,0);ax=bit32.lrotate(bit32.bxor(ax,aC),7)
end
end

local aJ=buffer.create(32)
buffer.writeu32(aJ,0,at)
buffer.writeu32(aJ,4,au)
buffer.writeu32(aJ,8,av)
buffer.writeu32(aJ,12,aw)
buffer.writeu32(aJ,16,aF)
buffer.writeu32(aJ,20,aG)
buffer.writeu32(aJ,24,aH)
buffer.writeu32(aJ,28,aI)

return aJ
end

function aa.XChaCha20(ak:buffer,al:buffer,am:buffer,an:number?,ao:number?):buffer
if am==nil then
error("Nonce cannot be nil",2)
end

if typeof(am)~="buffer"then
error(`Nonce must be a buffer, got {typeof(am)}`,2)
end

local ap=buffer.len(am)
if ap~=af then
error(`XChaCha20 requires a 24-byte nonce, got {ap} bytes`,2)
end

local aq=aa.HChaCha20(al,(function()
local aq=buffer.create(16)
buffer.copy(aq,0,am,0,16)
return aq
end)(),ao)

local ar=buffer.create(12)
buffer.copy(ar,4,am,16,8)

return aa.ChaCha20(ak,aq,ar,an,ao)
end

return aa end function a.A():typeof(__modImpl())local aa=a.cache.A if not aa then aa={c=__modImpl()}a.cache.A=aa end return aa.c end end do local function __modImpl()



















local aa=16
local ab=16
local ac=32

local function ProcessMessage(ad:buffer,ae:buffer):buffer
local af=buffer.len(ad)

local ag=ad
local ah=af

if af%ab~=0 or af==0 then
local ai=ab-(af%ab)
ah=af+ai
ag=buffer.create(ah)
buffer.copy(ag,0,ad,0,af)
buffer.writeu8(ag,af,1)
end

local ai=af-15

local aj=buffer.readu32(ae,0)%(268435456)
local ak=bit32.band(buffer.readu32(ae,4),0x0FFFFFFC)%(268435456)*(4294967296)
local al=bit32.band(buffer.readu32(ae,8),0x0FFFFFFC)%(268435456)*(1.8446744073709552E19)
local am=bit32.band(buffer.readu32(ae,12),0x0FFFFFFC)%(268435456)*(7922816251426434E13)

local an=aj%(262144)
local ao=aj-an
local ap=ak%(1125899906842624)
local aq=ak-ap
local ar=al%(4835703278458517E9)
local as=al-ar
local at=am%(5192296858534828E18)
local au=am-at

local av=3.6734198463196486E-39*ak
local aw=3.6734198463196486E-39*al
local ax=3.6734198463196486E-39*am

local ay=av%(8.271806125530277E-25)
local az=av-ay
local aA=aw%(3.552713678800501E-15)
local aB=aw-aA
local aC=ax%(1.52587890625E-5)
local aD=ax-aC

local aE,aF,aG,aH=0,0,0,0
local aI,aJ,aK,aL=0,0,0,0

for b=0,ah-1,ab do
local c=buffer.readu32(ag,b)
local d=buffer.readu32(ag,b+4)
local e=buffer.readu32(ag,b+8)
local f=buffer.readu32(ag,b+12)

local g=aE+aF+c
local h=aG+aH+d*(4294967296)
local i=aI+aJ+e*(1.8446744073709552E19)
local j=aK+aL+f*(7922816251426434E13)

if b<ai then
j=j+(34028236692093850E22)
end

aE=g*an+h*aC+i*aA+j*ay
aF=g*ao+h*aD+i*aB+j*az
aG=g*ap+h*an+i*aC+j*aA
aH=g*aq+h*ao+i*aD+j*aB
aI=g*ar+h*ap+i*an+j*aC
aJ=g*as+h*aq+i*ao+j*aD
aK=g*at+h*ar+i*ap+j*an
aL=g*au+h*as+i*aq+j*ao

local k=aE+1770887431076117E6-1770887431076117E6
aE-=k
aF+=k

local l=aF+290142196707511E11-290142196707511E11
aF-=l
aG+=l

local m=aG+7605903601369376E15-7605903601369376E15
aG-=m
aH+=m

local n=aH+12461512460483586E19-12461512460483586E19
aH-=n
aI+=n

local o=aI+32667107224410092E24-32667107224410092E24
aI-=o
aJ+=o

local p=aJ+5.3521788476473496E44-5.3521788476473496E44
aJ-=p
aK+=p

local q=aK+3507603929594167E34-3507603929594167E34
aK-=q
aL+=q

local r=aL+9.194973245195333E54-9.194973245195333E54
aL-=r

aE+=3.6734198463196486E-39*r
end

local b=aE%(65536)
aF=aE-b+aF

local c=aF%(4294967296)
aG=aF-c+aG

local d=aG%(281474976710656)
aH=aG-d+aH

local e=aH%(1.8446744073709552E19)
aI=aH-e+aI

local f=aI%(12089258196146292E8)
aJ=aI-f+aJ

local g=aJ%(7922816251426434E13)
aK=aJ-g+aK

local h=aK%(5192296858534828E18)
aL=aK-h+aL

local i=aL%(13611294676837538E23)

aE=b+3.6734198463196486E-39*(aL-i)
b=aE%(65536)
c=aE-b+c

if i==1.3611242753868953E39
and h==5.1922176303723134E33
and g==7922695358844472E13
and f==12089073728705554E8
and e==1844646259873284E4
and d==281470681743360
and c==4294901760
and b>=0xfffb
then
i,h,g,f=0,0,0,0
e,d,c=0,0,0
b-=0xfffb
end

local j=buffer.readu32(ae,16)
local k=buffer.readu32(ae,20)
local l=buffer.readu32(ae,24)
local m=buffer.readu32(ae,28)

local n=j+b+c
local o=n%(4294967296)

local p=n-o+k*(4294967296)+d+e
local q=p%(1.8446744073709552E19)

local r=p-q+l*(1.8446744073709552E19)+f+g
local s=r%(7922816251426434E13)

local t=r-s+m*(7922816251426434E13)+h+i
local u=t%(34028236692093850E22)

local v=buffer.create(aa)
buffer.writeu32(v,0,o)
buffer.writeu32(v,4,q/(4294967296))
buffer.writeu32(v,8,s/(1.8446744073709552E19))
buffer.writeu32(v,12,u/(7922816251426434E13))

return v
end

local function Poly1305(ad:buffer,ae:buffer):buffer
if ad==nil then
error("Message cannot be nil",2)
end

if typeof(ad)~="buffer"then
error(`Message must be a buffer, got {typeof(ad)}`,2)
end

if ae==nil then
error("Key cannot be nil",2)
end

if typeof(ae)~="buffer"then
error(`Key must be a buffer, got {typeof(ae)}`,2)
end

local af=buffer.len(ae)
if af~=ac then
error(`Key must be exactly {ac} bytes long, got {af} bytes`,2)
end

return ProcessMessage(ad,ae)
end

return Poly1305 end function a.B():typeof(__modImpl())local aa=a.cache.B if not aa then aa={c=__modImpl()}a.cache.B=aa end return aa.c end end do local function __modImpl()



























local aa=a.A()
local ab=a.B()

local ac=8

local ad=32
local ae=12
local af=24
local ag=16

local ah={
ChaCha20=aa.ChaCha20,
XChaCha20=aa.XChaCha20,
Poly1305=ab
}

local function GetFn(ai:boolean?):typeof(aa.ChaCha20)|typeof(aa.XChaCha20)
if ai then
return aa.XChaCha20
else
return aa.ChaCha20
end
end

local function ConstantTimeCompare(ai:buffer,aj:buffer):boolean
local ak=buffer.len(ai)
local al=buffer.len(aj)
if ak~=al then
return false
end

local am=0
for an=0,ak-1 do
am=bit32.bor(am,bit32.bxor(
buffer.readu8(ai,an),
buffer.readu8(aj,an)
))
end

return am==0
end

local function ConstructAuthData(ai:buffer,aj:buffer):buffer
local ak=buffer.len(ai)
local al=buffer.len(aj)

local am=(-ak)%16
local an=(-al)%16

local ao=ak+am+al+an+16
local ap=buffer.create(ao)
local aq=0

buffer.copy(ap,aq,ai,0,ak)
aq+=ak+am
buffer.copy(ap,aq,aj,0,al)
aq+=al+an
buffer.writeu32(ap,aq,ak)
buffer.writeu32(ap,aq+ac,al)

return ap
end

local function GenerateAuthKey(ai:buffer,aj:buffer,ak:number?,al:boolean?):buffer
local am=ak or 20
local an=buffer.create(32)

return GetFn(al)(an,ai,aj,0,am)
end

function ah.Encrypt(ai:buffer,aj:buffer,ak:buffer,al:buffer?,am:number?,an:boolean?):(buffer,buffer)
if ai==nil then
error("Message cannot be nil",2)
end

if typeof(ai)~="buffer"then
error(`Message must be a buffer, got {typeof(ai)}`,2)
end

local ao=buffer.len(ai)
if ao==0 then
error("Message cannot be empty",2)
end

if aj==nil then
error("Key cannot be nil",2)
end

if typeof(aj)~="buffer"then
error(`Key must be a buffer, got {typeof(aj)}`,2)
end

local ap=buffer.len(aj)
if ap~=ad then
error(`Key must be exactly {ad} bytes long, got {ap} bytes`,2)
end

if ak==nil then
error("Nonce cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Nonce must be a buffer, got {typeof(ak)}`,2)
end

local aq=buffer.len(ak)
local ar=if an then af else ae
if aq~=ar then
error(`Nonce must be exactly {ar} bytes long, got {aq} bytes`,2)
end

if al then
if typeof(al)~="buffer"then
error(`AdditionalAuthData must be a buffer, got {typeof(al)}`,2)
end
end

if am then
if typeof(am)~="number"then
error(`Rounds must be a number, got {typeof(am)}`,2)
end

if am<=0 then
error(`Rounds must be positive, got {am}`,2)
end

if am%2~=0 then
error(`Rounds must be even, got {am}`,2)
end
end

local as=am or 20
local at=al or buffer.create(0)

local au=GenerateAuthKey(aj,ak,as,an)
local av=GetFn(an)(ai,aj,ak,1,as)
local aw=ConstructAuthData(at,av)
local ax=ab(aw,au)

return av,ax
end

function ah.Decrypt(ai:buffer,aj:buffer,ak:buffer,al:buffer,am:buffer?,an:number?,ao:boolean?):buffer?
if ai==nil then
error("Ciphertext cannot be nil",2)
end

if typeof(ai)~="buffer"then
error(`Ciphertext must be a buffer, got {typeof(ai)}`,2)
end

local ap=buffer.len(ai)
if ap==0 then
error("Ciphertext cannot be empty",2)
end

if aj==nil then
error("Key cannot be nil",2)
end

if typeof(aj)~="buffer"then
error(`Key must be a buffer, got {typeof(aj)}`,2)
end

local aq=buffer.len(aj)
if aq~=ad then
error(`Key must be exactly {ad} bytes long, got {aq} bytes`,2)
end

if ak==nil then
error("Nonce cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Nonce must be a buffer, got {typeof(ak)}`,2)
end

local ar=buffer.len(ak)
local as=if ao then af else ae
if ar~=as then
error(`Nonce must be exactly {as} bytes long, got {ar} bytes`,2)
end

if al==nil then
error("Tag cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`Tag must be a buffer, got {typeof(al)}`,2)
end

local at=buffer.len(al)
if at~=ag then
error(`Tag must be exactly {ag} bytes long, got {at} bytes`,2)
end

if am then
if typeof(am)~="buffer"then
error(`AdditionalAuthData must be a buffer, got {typeof(am)}`,2)
end
end

if an then
if typeof(an)~="number"then
error(`Rounds must be a number, got {typeof(an)}`,2)
end

if an<=0 then
error(`Rounds must be positive, got {an}`,2)
end

if an%2~=0 then
error(`Rounds must be even, got {an}`,2)
end
end

local au=an or 20
local av=am or buffer.create(0)

local aw=GenerateAuthKey(aj,ak,au,ao)
local ax=ConstructAuthData(av,ai)
local ay=ab(ax,aw)

if not ConstantTimeCompare(al,ay)then
return nil
end

return GetFn(ao)(ai,aj,ak,1,au)
end

return ah end function a.C():typeof(__modImpl())local aa=a.cache.C if not aa then aa={c=__modImpl()}a.cache.C=aa end return aa.c end end do local function __modImpl()
























local aa={}

local ab=buffer.create(131072)
local ac=buffer.create(65536)
local ad=buffer.create(65536)

local ae=buffer.create(8192)
local af=buffer.create(2048)

local ag=buffer.create(65536)
local ah=buffer.create(65536)
local ai=buffer.create(65536)

local aj={
[16]={ExpandedLength=176,MaterialLength=128},
[24]={ExpandedLength=208,MaterialLength=160},
[32]={ExpandedLength=240,MaterialLength=192}
}

local ak,al=buffer.create(256),buffer.create(256)do
local am,an,ao=buffer.create(256),buffer.create(256),buffer.create(256)
local function GaloisFieldMultiply(ap:number,aq:number):number
local ar=0
for as=0,7 do
if aq%2==1 then
ar=bit32.bxor(ar,ap)
end
ap=ap>=128 and bit32.bxor(ap*2%256,27)or ap*2%256
aq=math.floor(aq/2)
end

return ar
end

local ap=1
local aq=1
buffer.writeu8(ak,0,99)

for ar=1,255 do
ap=bit32.bxor(ap,ap*2,ap<128 and 0 or 27)%256
aq=bit32.bxor(aq,aq*2)
aq=bit32.bxor(aq,aq*4)
aq=bit32.bxor(aq,aq*16)%256
if aq>=128 then
aq=bit32.bxor(aq,9)
end

local as=bit32.bxor(
aq,
aq%128*2+aq/128,
aq%64*4+aq/64,
aq%32*8+aq/32,
aq%16*16+aq/16,
99
)
buffer.writeu8(ak,ap,as)
buffer.writeu8(al,as,ap)
buffer.writeu8(am,ap,GaloisFieldMultiply(3,ap))
buffer.writeu8(an,ap,GaloisFieldMultiply(9,ap))
buffer.writeu8(ao,ap,GaloisFieldMultiply(11,ap))
end

local ar=0
for as=0,255 do
local at=buffer.readu8(ak,as)
local au=at*256
local av=GaloisFieldMultiply(2,at)
local aw=GaloisFieldMultiply(13,as)
local ax=GaloisFieldMultiply(14,as)

for ay=0,255 do
local az=buffer.readu8(ak,ay)

buffer.writeu16(ab,ar*2,au+az)
buffer.writeu8(ag,ar,buffer.readu8(al,bit32.bxor(as,ay)))
buffer.writeu8(ac,ar,bit32.bxor(av,buffer.readu8(am,az)))
buffer.writeu8(ad,ar,bit32.bxor(at,az))
buffer.writeu8(ah,ar,bit32.bxor(ax,buffer.readu8(ao,ay)))
buffer.writeu8(ai,ar,bit32.bxor(aw,buffer.readu8(an,ay)))
ar+=1
end
end
end

local function ExpandKeySchedule(am:buffer,an:number,ao:buffer):buffer
buffer.copy(ao,0,am,0,an)

local ap=bit32.rrotate(buffer.readu32(ao,an-4),8)
local aq=0.5
local ar=ab

if an==32 then
for as=32,192,32 do
aq=aq*2%229
local at=buffer.readu16(ar,ap//65536*2)*65536+buffer.readu16(ar,ap%65536*2)
ap=bit32.bxor(buffer.readu32(ao,as-32),at,aq)
buffer.writeu32(ao,as,ap)

local au=bit32.bxor(buffer.readu32(ao,as-28),ap)
buffer.writeu32(ao,as+4,au)
local av=bit32.bxor(buffer.readu32(ao,as-24),au)
buffer.writeu32(ao,as+8,av)
local aw=bit32.bxor(buffer.readu32(ao,as-20),av)
buffer.writeu32(ao,as+12,aw)

at=buffer.readu16(ar,aw//65536*2)*65536+buffer.readu16(ar,aw%65536*2)
ap=bit32.bxor(buffer.readu32(ao,as-16),at)
buffer.writeu32(ao,as+16,ap)

au=bit32.bxor(buffer.readu32(ao,as-12),ap)
buffer.writeu32(ao,as+20,au)
av=bit32.bxor(buffer.readu32(ao,as-8),au)
buffer.writeu32(ao,as+24,av)
ap=bit32.bxor(buffer.readu32(ao,as-4),av)
buffer.writeu32(ao,as+28,ap)
ap=bit32.rrotate(ap,8)
end

local as=buffer.readu16(ar,ap//65536*2)*65536+buffer.readu16(ar,ap%65536*2)
ap=bit32.bxor(buffer.readu32(ao,192),as,64)
buffer.writeu32(ao,224,ap)

local at=bit32.bxor(buffer.readu32(ao,196),ap)
buffer.writeu32(ao,228,at)
local au=bit32.bxor(buffer.readu32(ao,200),at)
buffer.writeu32(ao,232,au)
buffer.writeu32(ao,236,bit32.bxor(buffer.readu32(ao,204),au))

elseif an==24 then
for as=24,168,24 do
aq=aq*2%229
local at=buffer.readu16(ar,ap//65536*2)*65536+buffer.readu16(ar,ap%65536*2)
ap=bit32.bxor(buffer.readu32(ao,as-24),at,aq)
buffer.writeu32(ao,as,ap)

local au=bit32.bxor(buffer.readu32(ao,as-20),ap)
buffer.writeu32(ao,as+4,au)
local av=bit32.bxor(buffer.readu32(ao,as-16),au)
buffer.writeu32(ao,as+8,av)
local aw=bit32.bxor(buffer.readu32(ao,as-12),av)
buffer.writeu32(ao,as+12,aw)
local ax=bit32.bxor(buffer.readu32(ao,as-8),aw)
buffer.writeu32(ao,as+16,ax)
ap=bit32.bxor(buffer.readu32(ao,as-4),ax)
buffer.writeu32(ao,as+20,ap)
ap=bit32.rrotate(ap,8)
end

local as=buffer.readu16(ar,ap//65536*2)*65536+buffer.readu16(ar,ap%65536*2)
ap=bit32.bxor(buffer.readu32(ao,168),as,128)
buffer.writeu32(ao,192,ap)

local at=bit32.bxor(buffer.readu32(ao,172),ap)
buffer.writeu32(ao,196,at)
local au=bit32.bxor(buffer.readu32(ao,176),at)
buffer.writeu32(ao,200,au)
buffer.writeu32(ao,204,bit32.bxor(buffer.readu32(ao,180),au))
else
for as=16,144,16 do
aq=aq*2%229
local at=buffer.readu16(ar,ap//65536*2)*65536+buffer.readu16(ar,ap%65536*2)
ap=bit32.bxor(buffer.readu32(ao,as-16),at,aq)
buffer.writeu32(ao,as,ap)

local au=bit32.bxor(buffer.readu32(ao,as-12),ap)
buffer.writeu32(ao,as+4,au)
local av=bit32.bxor(buffer.readu32(ao,as-8),au)
buffer.writeu32(ao,as+8,av)
ap=bit32.bxor(buffer.readu32(ao,as-4),av)
buffer.writeu32(ao,as+12,ap)
ap=bit32.rrotate(ap,8)
end

local as=buffer.readu16(ar,ap//65536*2)*65536+buffer.readu16(ar,ap%65536*2)
ap=bit32.bxor(buffer.readu32(ao,144),as,54)
buffer.writeu32(ao,160,ap)

local at=bit32.bxor(buffer.readu32(ao,148),ap)
buffer.writeu32(ao,164,at)
local au=bit32.bxor(buffer.readu32(ao,152),at)
buffer.writeu32(ao,168,au)
buffer.writeu32(ao,172,bit32.bxor(buffer.readu32(ao,156),au))
end

return ao
end

local am:number,an:number,ao:number,ap:number,aq:number,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number,aA:number,aB:number
local function EncryptBlock(aC:buffer,aD:number,aE:buffer,aF:number,aG:buffer,aH:number)
am=bit32.bxor(buffer.readu8(aE,aF),buffer.readu8(aC,0))
an=bit32.bxor(buffer.readu8(aE,aF+1),buffer.readu8(aC,1))
ao=bit32.bxor(buffer.readu8(aE,aF+2),buffer.readu8(aC,2))
ap=bit32.bxor(buffer.readu8(aE,aF+3),buffer.readu8(aC,3))
aq=bit32.bxor(buffer.readu8(aE,aF+4),buffer.readu8(aC,4))
ar=bit32.bxor(buffer.readu8(aE,aF+5),buffer.readu8(aC,5))
as=bit32.bxor(buffer.readu8(aE,aF+6),buffer.readu8(aC,6))
at=bit32.bxor(buffer.readu8(aE,aF+7),buffer.readu8(aC,7))
au=bit32.bxor(buffer.readu8(aE,aF+8),buffer.readu8(aC,8))
av=bit32.bxor(buffer.readu8(aE,aF+9),buffer.readu8(aC,9))
aw=bit32.bxor(buffer.readu8(aE,aF+10),buffer.readu8(aC,10))
ax=bit32.bxor(buffer.readu8(aE,aF+11),buffer.readu8(aC,11))
ay=bit32.bxor(buffer.readu8(aE,aF+12),buffer.readu8(aC,12))
az=bit32.bxor(buffer.readu8(aE,aF+13),buffer.readu8(aC,13))
aA=bit32.bxor(buffer.readu8(aE,aF+14),buffer.readu8(aC,14))
aB=bit32.bxor(buffer.readu8(aE,aF+15),buffer.readu8(aC,15))

local aI:number,aJ:number,aK:number,aL:number,b:number,c:number,d:number,e:number,f:number,g:number,h:number,i:number,j:number,k:number,l:number,m:number
=am,an,ao,ap,aq,ar,as,at,au,av,aw,ax,ay,az,aA,aB

local n:number=aI*256+c;local o:number=c*256+h;local p:number=h*256+m;local q:number=m*256+aI
local r:number=b*256+g;local s:number=g*256+l;local t:number=l*256+aL;local u:number=aL*256+b
local v:number=f*256+k;local w:number=k*256+aK;local x:number=aK*256+e;local y:number=e*256+f
local z:number=j*256+aJ;local A:number=aJ*256+d;local B:number=d*256+i;local C:number=i*256+j

local D,E=ac,ad
for F=16,aD,16 do
aI=bit32.bxor(buffer.readu8(D,n),buffer.readu8(E,p),buffer.readu8(aC,F))
aJ=bit32.bxor(buffer.readu8(D,o),buffer.readu8(E,q),buffer.readu8(aC,F+1))
aK=bit32.bxor(buffer.readu8(D,p),buffer.readu8(E,n),buffer.readu8(aC,F+2))
aL=bit32.bxor(buffer.readu8(D,q),buffer.readu8(E,o),buffer.readu8(aC,F+3))
b=bit32.bxor(buffer.readu8(D,r),buffer.readu8(E,t),buffer.readu8(aC,F+4))
c=bit32.bxor(buffer.readu8(D,s),buffer.readu8(E,u),buffer.readu8(aC,F+5))
d=bit32.bxor(buffer.readu8(D,t),buffer.readu8(E,r),buffer.readu8(aC,F+6))
e=bit32.bxor(buffer.readu8(D,u),buffer.readu8(E,s),buffer.readu8(aC,F+7))
f=bit32.bxor(buffer.readu8(D,v),buffer.readu8(E,x),buffer.readu8(aC,F+8))
g=bit32.bxor(buffer.readu8(D,w),buffer.readu8(E,y),buffer.readu8(aC,F+9))
h=bit32.bxor(buffer.readu8(D,x),buffer.readu8(E,v),buffer.readu8(aC,F+10))
i=bit32.bxor(buffer.readu8(D,y),buffer.readu8(E,w),buffer.readu8(aC,F+11))
j=bit32.bxor(buffer.readu8(D,z),buffer.readu8(E,B),buffer.readu8(aC,F+12))
k=bit32.bxor(buffer.readu8(D,A),buffer.readu8(E,C),buffer.readu8(aC,F+13))
l=bit32.bxor(buffer.readu8(D,B),buffer.readu8(E,z),buffer.readu8(aC,F+14))
m=bit32.bxor(buffer.readu8(D,C),buffer.readu8(E,A),buffer.readu8(aC,F+15))

n,o,p,q=aI*256+c,c*256+h,h*256+m,m*256+aI
r,s,t,u=b*256+g,g*256+l,l*256+aL,aL*256+b
v,w,x,y=f*256+k,k*256+aK,aK*256+e,e*256+f
z,A,B,C=j*256+aJ,aJ*256+d,d*256+i,i*256+j
end

buffer.writeu32(aG,aH,bit32.bxor(
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,C),buffer.readu8(ad,A),buffer.readu8(aC,aD+31))*512+
bit32.bxor(buffer.readu8(D,x),buffer.readu8(ad,v),buffer.readu8(aC,aD+26))*2)*65536+
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,s),buffer.readu8(ad,u),buffer.readu8(aC,aD+21))*512+
bit32.bxor(buffer.readu8(D,n),buffer.readu8(ad,p),buffer.readu8(aC,aD+16))*2),
buffer.readu32(aC,aD+32)
))

buffer.writeu32(aG,aH+4,bit32.bxor(
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,q),buffer.readu8(ad,o),buffer.readu8(aC,aD+19))*512+
bit32.bxor(buffer.readu8(D,B),buffer.readu8(ad,z),buffer.readu8(aC,aD+30))*2)*65536+
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,w),buffer.readu8(ad,y),buffer.readu8(aC,aD+25))*512+
bit32.bxor(buffer.readu8(D,r),buffer.readu8(ad,t),buffer.readu8(aC,aD+20))*2),
buffer.readu32(aC,aD+36)
))

buffer.writeu32(aG,aH+8,bit32.bxor(
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,u),buffer.readu8(ad,s),buffer.readu8(aC,aD+23))*512+
bit32.bxor(buffer.readu8(D,p),buffer.readu8(ad,n),buffer.readu8(aC,aD+18))*2)*65536+
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,A),buffer.readu8(ad,C),buffer.readu8(aC,aD+29))*512+
bit32.bxor(buffer.readu8(D,v),buffer.readu8(ad,x),buffer.readu8(aC,aD+24))*2),
buffer.readu32(aC,aD+40)
))

buffer.writeu32(aG,aH+12,bit32.bxor(
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,y),buffer.readu8(ad,w),buffer.readu8(aC,aD+27))*512+
bit32.bxor(buffer.readu8(D,t),buffer.readu8(ad,r),buffer.readu8(aC,aD+22))*2)*65536+
buffer.readu16(ab,bit32.bxor(buffer.readu8(D,o),buffer.readu8(ad,q),buffer.readu8(aC,aD+17))*512+
bit32.bxor(buffer.readu8(D,z),buffer.readu8(ad,B),buffer.readu8(aC,aD+28))*2),
buffer.readu32(aC,aD+44)
))
end

local function ConstantTimeCompare(aC:buffer,aD:buffer):boolean
local aE=buffer.len(aC)
local aF=buffer.len(aD)
if aE~=aF then
return false
end

local aG=0
for aH=0,aE-1 do
aG=bit32.bor(aG,bit32.bxor(
buffer.readu8(aC,aH),
buffer.readu8(aD,aH)
))
end

return aG==0
end

local function BuildShoupTables(aC:buffer):buffer
local aD=af
local aE=ae

buffer.copy(aD,0,aC,0,16)

for aF=1,127 do
local aG=(aF-1)*16
local aH=aF*16

local aI=bit32.band(buffer.readu8(aD,aG+15),1)

local aJ=0
for aK=0,15 do
local aL=buffer.readu8(aD,aG+aK)
local b=bit32.lshift(bit32.band(aL,1),7)
buffer.writeu8(aD,aH+aK,bit32.bor(bit32.rshift(aL,1),aJ))
aJ=b
end

if aI==1 then
buffer.writeu8(aD,aH,bit32.bxor(buffer.readu8(aD,aH),0xE1))
end
end

for aF=0,31 do
local aG=aF*256

buffer.writeu32(aE,aG,0)
buffer.writeu32(aE,aG+4,0)
buffer.writeu32(aE,aG+8,0)
buffer.writeu32(aE,aG+12,0)

for aH=1,15 do
local aI=aG+aH*16
local aJ,aK,aL,b=0,0,0,0

for c=0,3 do
if bit32.band(aH,bit32.lshift(1,3-c))~=0 then
local d=(aF*4+c)*16

aJ=bit32.bxor(aJ,buffer.readu32(aD,d))
aK=bit32.bxor(aK,buffer.readu32(aD,d+4))
aL=bit32.bxor(aL,buffer.readu32(aD,d+8))
b=bit32.bxor(b,buffer.readu32(aD,d+12))
end
end

buffer.writeu32(aE,aI,aJ)
buffer.writeu32(aE,aI+4,aK)
buffer.writeu32(aE,aI+8,aL)
buffer.writeu32(aE,aI+12,b)
end
end

return aE
end

local function GfMult(aC:buffer,aD:buffer,aE:buffer)
local aF,aG,aH,aI=0,0,0,0

for aJ=0,15 do
local aK=buffer.readu8(aC,aJ)
local aL=aJ*512

local b=aL+bit32.rshift(aK,4)*16
aF=bit32.bxor(aF,buffer.readu32(aD,b))
aG=bit32.bxor(aG,buffer.readu32(aD,b+4))
aH=bit32.bxor(aH,buffer.readu32(aD,b+8))
aI=bit32.bxor(aI,buffer.readu32(aD,b+12))

local c=aL+256+bit32.band(aK,0x0F)*16
aF=bit32.bxor(aF,buffer.readu32(aD,c))
aG=bit32.bxor(aG,buffer.readu32(aD,c+4))
aH=bit32.bxor(aH,buffer.readu32(aD,c+8))
aI=bit32.bxor(aI,buffer.readu32(aD,c+12))
end

buffer.writeu32(aE,0,aF)
buffer.writeu32(aE,4,aG)
buffer.writeu32(aE,8,aH)
buffer.writeu32(aE,12,aI)
end

local function Ghash(aC:buffer,aD:buffer,aE:number,aF:buffer)
local aG=math.floor(aE/16)
local aH=0
local aI=buffer.create(16)
local aJ=GfMult

for aK=1,aG do
buffer.writeu32(aF,0,bit32.bxor(buffer.readu32(aF,0),buffer.readu32(aD,aH)))
buffer.writeu32(aF,4,bit32.bxor(buffer.readu32(aF,4),buffer.readu32(aD,aH+4)))
buffer.writeu32(aF,8,bit32.bxor(buffer.readu32(aF,8),buffer.readu32(aD,aH+8)))
buffer.writeu32(aF,12,bit32.bxor(buffer.readu32(aF,12),buffer.readu32(aD,aH+12)))
aH+=16

aJ(aF,aC,aI)

buffer.writeu32(aF,0,buffer.readu32(aI,0))
buffer.writeu32(aF,4,buffer.readu32(aI,4))
buffer.writeu32(aF,8,buffer.readu32(aI,8))
buffer.writeu32(aF,12,buffer.readu32(aI,12))
end

if aH<aE then
local aK=aE-aH
buffer.writeu32(aI,0,0)
buffer.writeu32(aI,4,0)
buffer.writeu32(aI,8,0)
buffer.writeu32(aI,12,0)
buffer.copy(aI,0,aD,aH,aK)

buffer.writeu32(aF,0,bit32.bxor(buffer.readu32(aF,0),buffer.readu32(aI,0)))
buffer.writeu32(aF,4,bit32.bxor(buffer.readu32(aF,4),buffer.readu32(aI,4)))
buffer.writeu32(aF,8,bit32.bxor(buffer.readu32(aF,8),buffer.readu32(aI,8)))
buffer.writeu32(aF,12,bit32.bxor(buffer.readu32(aF,12),buffer.readu32(aI,12)))

aJ(aF,aC,aI)

buffer.writeu32(aF,0,buffer.readu32(aI,0))
buffer.writeu32(aF,4,buffer.readu32(aI,4))
buffer.writeu32(aF,8,buffer.readu32(aI,8))
buffer.writeu32(aF,12,buffer.readu32(aI,12))
end
end

local function Gctr(aC:buffer,aD:number,aE:buffer,aF:buffer,aG:number,aH:buffer)
if aG==0 then
return
end

local aI=math.floor(aG/16)
local aJ=buffer.create(16)
local aK=buffer.create(16)
local aL=0
local b=0

buffer.writeu32(aJ,0,buffer.readu32(aE,0))
buffer.writeu32(aJ,4,buffer.readu32(aE,4))
buffer.writeu32(aJ,8,buffer.readu32(aE,8))
buffer.writeu32(aJ,12,buffer.readu32(aE,12))

local c=EncryptBlock

for d=0,aI-1 do
c(aC,aD,aJ,0,aK,0)

buffer.writeu32(aH,b+0,bit32.bxor(buffer.readu32(aF,aL+0),buffer.readu32(aK,0)))
buffer.writeu32(aH,b+4,bit32.bxor(buffer.readu32(aF,aL+4),buffer.readu32(aK,4)))
buffer.writeu32(aH,b+8,bit32.bxor(buffer.readu32(aF,aL+8),buffer.readu32(aK,8)))
buffer.writeu32(aH,b+12,bit32.bxor(buffer.readu32(aF,aL+12),buffer.readu32(aK,12)))

aL+=16
b+=16

local e=bit32.byteswap(buffer.readu32(aJ,12))
e=(e+1)%0x100000000
buffer.writeu32(aJ,12,bit32.byteswap(e))
end

local d=aG-aL
if d>0 then
EncryptBlock(aC,aD,aJ,0,aK,0)
for e=0,d-1 do
local f=buffer.readu8(aF,aL+e)
local g=buffer.readu8(aK,e)
buffer.writeu8(aH,b+e,bit32.bxor(f,g))
end
end
end

local function PrepareJ0(aC:buffer,aD:buffer,aE:number,aF:buffer):buffer
local aG=BuildShoupTables(aC)

if aE==12 then
buffer.writeu32(aF,0,buffer.readu32(aD,0))
buffer.writeu32(aF,4,buffer.readu32(aD,4))
buffer.writeu32(aF,8,buffer.readu32(aD,8))
buffer.writeu32(aF,12,0x01000000)
else
buffer.writeu32(aF,0,0)
buffer.writeu32(aF,4,0)
buffer.writeu32(aF,8,0)
buffer.writeu32(aF,12,0)

Ghash(aG,aD,aE,aF)

local aH=buffer.create(16)
local aI=aE*8

buffer.writeu32(aH,0,0)
buffer.writeu32(aH,4,0)
buffer.writeu32(aH,8,0)
buffer.writeu32(aH,12,bit32.byteswap(aI))

Ghash(aG,aH,16,aF)
end

return aG
end

local function GcmGctr(aC:buffer,aD:number,aE:buffer,aF:buffer,aG:number,aH:buffer)
if aG==0 then
return
end

local aI=buffer.create(16)

buffer.writeu32(aI,0,buffer.readu32(aE,0))
buffer.writeu32(aI,4,buffer.readu32(aE,4))
buffer.writeu32(aI,8,buffer.readu32(aE,8))
buffer.writeu32(aI,12,buffer.readu32(aE,12))

local aJ=bit32.byteswap(buffer.readu32(aI,12))
aJ=(aJ+1)%0x100000000
buffer.writeu32(aI,12,bit32.byteswap(aJ))

Gctr(aC,aD,aI,aF,aG,aH)
end

local function GcmHash(aC:buffer,aD:buffer,aE:number,aF:buffer,aG:number,aH:buffer)
local aI=buffer.create(16)
local aJ=GfMult

buffer.writeu32(aH,0,0)
buffer.writeu32(aH,4,0)
buffer.writeu32(aH,8,0)
buffer.writeu32(aH,12,0)

local aK=math.floor(aE/16)
local aL=0

for b=1,aK do
buffer.writeu32(aH,0,bit32.bxor(buffer.readu32(aH,0),buffer.readu32(aD,aL)))
buffer.writeu32(aH,4,bit32.bxor(buffer.readu32(aH,4),buffer.readu32(aD,aL+4)))
buffer.writeu32(aH,8,bit32.bxor(buffer.readu32(aH,8),buffer.readu32(aD,aL+8)))
buffer.writeu32(aH,12,bit32.bxor(buffer.readu32(aH,12),buffer.readu32(aD,aL+12)))
aL+=16

aJ(aH,aC,aI)

buffer.writeu32(aH,0,buffer.readu32(aI,0))
buffer.writeu32(aH,4,buffer.readu32(aI,4))
buffer.writeu32(aH,8,buffer.readu32(aI,8))
buffer.writeu32(aH,12,buffer.readu32(aI,12))
end

if aL<aE then
local b=aE-aL
buffer.writeu32(aI,0,0)
buffer.writeu32(aI,4,0)
buffer.writeu32(aI,8,0)
buffer.writeu32(aI,12,0)
buffer.copy(aI,0,aD,aL,b)

buffer.writeu32(aH,0,bit32.bxor(buffer.readu32(aH,0),buffer.readu32(aI,0)))
buffer.writeu32(aH,4,bit32.bxor(buffer.readu32(aH,4),buffer.readu32(aI,4)))
buffer.writeu32(aH,8,bit32.bxor(buffer.readu32(aH,8),buffer.readu32(aI,8)))
buffer.writeu32(aH,12,bit32.bxor(buffer.readu32(aH,12),buffer.readu32(aI,12)))

aJ(aH,aC,aI)

buffer.writeu32(aH,0,buffer.readu32(aI,0))
buffer.writeu32(aH,4,buffer.readu32(aI,4))
buffer.writeu32(aH,8,buffer.readu32(aI,8))
buffer.writeu32(aH,12,buffer.readu32(aI,12))
end

aK=math.floor(aG/16)
aL=0

for b=1,aK do
buffer.writeu32(aH,0,bit32.bxor(buffer.readu32(aH,0),buffer.readu32(aF,aL)))
buffer.writeu32(aH,4,bit32.bxor(buffer.readu32(aH,4),buffer.readu32(aF,aL+4)))
buffer.writeu32(aH,8,bit32.bxor(buffer.readu32(aH,8),buffer.readu32(aF,aL+8)))
buffer.writeu32(aH,12,bit32.bxor(buffer.readu32(aH,12),buffer.readu32(aF,aL+12)))
aL+=16

aJ(aH,aC,aI)

buffer.writeu32(aH,0,buffer.readu32(aI,0))
buffer.writeu32(aH,4,buffer.readu32(aI,4))
buffer.writeu32(aH,8,buffer.readu32(aI,8))
buffer.writeu32(aH,12,buffer.readu32(aI,12))
end

if aL<aG then
local b=aG-aL
buffer.writeu32(aI,0,0)
buffer.writeu32(aI,4,0)
buffer.writeu32(aI,8,0)
buffer.writeu32(aI,12,0)
buffer.copy(aI,0,aF,aL,b)

buffer.writeu32(aH,0,bit32.bxor(buffer.readu32(aH,0),buffer.readu32(aI,0)))
buffer.writeu32(aH,4,bit32.bxor(buffer.readu32(aH,4),buffer.readu32(aI,4)))
buffer.writeu32(aH,8,bit32.bxor(buffer.readu32(aH,8),buffer.readu32(aI,8)))
buffer.writeu32(aH,12,bit32.bxor(buffer.readu32(aH,12),buffer.readu32(aI,12)))

aJ(aH,aC,aI)

buffer.writeu32(aH,0,buffer.readu32(aI,0))
buffer.writeu32(aH,4,buffer.readu32(aI,4))
buffer.writeu32(aH,8,buffer.readu32(aI,8))
buffer.writeu32(aH,12,buffer.readu32(aI,12))
end

local b=aE*8
local c=aG*8

buffer.writeu32(aH,4,bit32.bxor(buffer.readu32(aH,4),bit32.byteswap(b)))
buffer.writeu32(aH,12,bit32.bxor(buffer.readu32(aH,12),bit32.byteswap(c)))

aJ(aH,aC,aI)

buffer.writeu32(aH,0,buffer.readu32(aI,0))
buffer.writeu32(aH,4,buffer.readu32(aI,4))
buffer.writeu32(aH,8,buffer.readu32(aI,8))
buffer.writeu32(aH,12,buffer.readu32(aI,12))
end

function aa.Encrypt(aC:buffer,aD:buffer,aE:buffer,aF:buffer?):(buffer,buffer)
if not aD or typeof(aD)~="buffer"then
error("Key must be a buffer",2)
end

if not aE or typeof(aE)~="buffer"then
error("IV must be a buffer",2)
end

if not aC or typeof(aC)~="buffer"then
error("Plaintext must be a buffer",2)
end

local aG=buffer.len(aD)
if aG~=16 and aG~=24 and aG~=32 then
error("Key must be 16, 24, or 32 bytes",2)
end

local aH=aj[aG]
local aI=ExpandKeySchedule(aD,aG,buffer.create(aH.ExpandedLength))
local aJ=aH.MaterialLength

local aK=buffer.len(aE)
local aL=buffer.len(aF or buffer.create(0))
local b=buffer.len(aC)
local c=aF or buffer.create(0)

local d=buffer.create(b)
local e=buffer.create(16)

local f=buffer.create(16)
local g=buffer.create(16)
local h=buffer.create(16)

EncryptBlock(aI,aJ,f,0,f,0)
local i=PrepareJ0(f,aE,aK,g)
GcmGctr(aI,aJ,g,aC,b,d)
GcmHash(i,c,aL,d,b,h)
Gctr(aI,aJ,g,h,16,e)

return d,e
end

function aa.Decrypt(aC:buffer,aD:buffer,aE:buffer,aF:buffer,aG:buffer?):(boolean,buffer?)
if not aD or typeof(aD)~="buffer"then
error("Key must be a buffer",2)
end

if not aE or typeof(aE)~="buffer"then
error("IV must be a buffer",2)
end

if not aC or typeof(aC)~="buffer"then
error("Ciphertext must be a buffer",2)
end

if not aF or typeof(aF)~="buffer"then
error("Tag must be a buffer",2)
end

local aH=buffer.len(aD)
if aH~=16 and aH~=24 and aH~=32 then
error("Key must be 16, 24, or 32 bytes",2)
end

local aI=aj[aH]
local aJ=ExpandKeySchedule(aD,aH,buffer.create(aI.ExpandedLength))
local aK=aI.MaterialLength

local aL=buffer.len(aE)
local b=buffer.len(aG or buffer.create(0))
local c=buffer.len(aC)
local d=aG or buffer.create(0)

local e=buffer.create(c)

local f=buffer.create(16)
local g=buffer.create(16)
local h=buffer.create(16)
local i=buffer.create(16)

EncryptBlock(aJ,aK,f,0,f,0)
local j=PrepareJ0(f,aE,aL,g)
GcmGctr(aJ,aK,g,aC,c,e)
GcmHash(j,d,b,aC,c,h)
Gctr(aJ,aK,g,h,16,i)

if not ConstantTimeCompare(aF,i)then
return false,nil
end

return true,e
end

return aa end function a.D():typeof(__modImpl())local aa=a.cache.D if not aa then aa={c=__modImpl()}a.cache.D=aa end return aa.c end end do local function __modImpl()




















local function XOR(aa:buffer,ab:buffer):buffer
local ac=buffer.len(aa)
local ad=buffer.len(ab)

local ae=buffer.create(ac)
buffer.copy(ae,0,aa,0,ac)

if ad==1 then
local af=buffer.readu8(ab,0)
local ag=bit32.bor(
af,
bit32.lshift(af,8),
bit32.lshift(af,16),
bit32.lshift(af,24)
)

local ah=0
while ah+3<ac do
buffer.writeu32(ae,ah,bit32.bxor(buffer.readu32(ae,ah),ag))
ah+=4
end

while ah<ac do
buffer.writeu8(ae,ah,bit32.bxor(buffer.readu8(ae,ah),af))
ah+=1
end

return ae
end

if ad==4 then
local af=buffer.readu32(ab,0)
local ag=0
while ag+3<ac do
buffer.writeu32(ae,ag,bit32.bxor(buffer.readu32(ae,ag),af))
ag+=4
end

for ah=0,ac-ag-1 do
local ai=ag+ah
buffer.writeu8(ae,ai,bit32.bxor(
buffer.readu8(ae,ai),
buffer.readu8(ab,ah)
))
end

return ae
end

local af=math.min(ac,ad*256)
local ag=buffer.create(af)

local ah=0
while ah<af do
local ai=math.min(ad,af-ah)
buffer.copy(ag,ah,ab,0,ai)
ah+=ai
end

local ai=0
while ai<ac do
local aj=math.min(af,ac-ai)
local ak=0

while ak+3<aj and ai+ak+3<ac do
local al=ai+ak
buffer.writeu32(ae,al,bit32.bxor(
buffer.readu32(ae,al),
buffer.readu32(ag,ak)
))
ak+=4
end

while ak<aj and ai+ak<ac do
local al=ai+ak
buffer.writeu8(ae,al,bit32.bxor(
buffer.readu8(ae,al),
buffer.readu8(ag,ak)
))
ak+=1
end

ai+=aj
end

return ae
end

return XOR end function a.E():typeof(__modImpl())local aa=a.cache.E if not aa then aa={c=__modImpl()}a.cache.E=aa end return aa.c end end do local function __modImpl()






















local aa:number=44
local ab:number=4
local ac:number=8

local ad:{number}={
1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,
1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,
0,1,0,0,1,0,0,0,1,1,1,0,0,1,1,1,
1,0,1,0,0,0,0,1,1,0,0,0,1,1
}

local ae={}

local function GenerateKeySchedule(af:buffer):buffer
local ag=buffer.create(176)

buffer.writeu32(ag,0,buffer.readu32(af,0))
buffer.writeu32(ag,4,buffer.readu32(af,4))
buffer.writeu32(ag,8,buffer.readu32(af,8))
buffer.writeu32(ag,12,buffer.readu32(af,12))

for ah=ab,aa-1 do
local ai=buffer.readu32(ag,(ah-1)*4)
local aj=bit32.bxor(bit32.rrotate(ai,3),buffer.readu32(ag,(ah-3)*4))
local ak=bit32.rrotate(aj,1)

local al=ad[((ah-ab)%62)+1]
buffer.writeu32(ag,ah*4,bit32.bxor(bit32.bxor(buffer.readu32(ag,(ah-ab)*4),bit32.bxor(aj,ak)),bit32.bxor(3,al)))
end

return ag
end

local function EncryptBlocks(af:buffer,ag:buffer,ah:buffer,ai:number):()
for aj=0,ai-1,ac do
local ak=buffer.readu32(ag,aj)
local al=buffer.readu32(ag,aj+4)

for am=0,(aa-1)*4,16 do
ak,al=bit32.bxor(al,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(ak,1),bit32.lrotate(ak,8)),bit32.lrotate(ak,2)),buffer.readu32(ah,am))),ak
ak,al=bit32.bxor(al,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(ak,1),bit32.lrotate(ak,8)),bit32.lrotate(ak,2)),buffer.readu32(ah,am+4))),ak
ak,al=bit32.bxor(al,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(ak,1),bit32.lrotate(ak,8)),bit32.lrotate(ak,2)),buffer.readu32(ah,am+8))),ak
ak,al=bit32.bxor(al,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(ak,1),bit32.lrotate(ak,8)),bit32.lrotate(ak,2)),buffer.readu32(ah,am+12))),ak
end

buffer.writeu32(af,aj,ak)
buffer.writeu32(af,aj+4,al)
end
end

local function DecryptBlocks(af:buffer,ag:buffer,ah:buffer,ai:number):()
for aj=0,ai-1,ac do
local ak=buffer.readu32(ag,aj)
local al=buffer.readu32(ag,aj+4)

for am=(aa-1)*4,0,-16 do
al,ak=bit32.bxor(ak,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(al,1),bit32.lrotate(al,8)),bit32.lrotate(al,2)),buffer.readu32(ah,am))),al
al,ak=bit32.bxor(ak,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(al,1),bit32.lrotate(al,8)),bit32.lrotate(al,2)),buffer.readu32(ah,am-4))),al
al,ak=bit32.bxor(ak,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(al,1),bit32.lrotate(al,8)),bit32.lrotate(al,2)),buffer.readu32(ah,am-8))),al
al,ak=bit32.bxor(ak,bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(al,1),bit32.lrotate(al,8)),bit32.lrotate(al,2)),buffer.readu32(ah,am-12))),al
end

buffer.writeu32(af,aj,ak)
buffer.writeu32(af,aj+4,al)
end
end

local function PadBuffer(af:buffer):buffer
local ag=buffer.len(af)
local ah=ac-(ag%ac)
local ai=buffer.create(ag+ah)

buffer.copy(ai,0,af,0,ag)

if ah==1 then
buffer.writeu8(ai,ag,ah)
elseif ah==2 then
buffer.writeu16(ai,ag,ah*0x0101)
elseif ah==4 then
buffer.writeu32(ai,ag,ah*0x01010101)
else
for aj=ag,ag+ah-1 do
buffer.writeu8(ai,aj,ah)
end
end

return ai
end

local function UnpadBuffer(af:buffer):buffer
local ag=buffer.len(af)
if ag==0 then
return af
end

local ah=buffer.readu8(af,ag-1)
local ai=buffer.create(ag-ah)

buffer.copy(ai,0,af,0,ag-ah)

return ai
end

local function PrepareKey(af:buffer):buffer
local ag=buffer.len(af)
local ah=buffer.create(16)

if ag>=16 then
buffer.writeu32(ah,0,buffer.readu32(af,0))
buffer.writeu32(ah,4,buffer.readu32(af,4))
buffer.writeu32(ah,8,buffer.readu32(af,8))
buffer.writeu32(ah,12,buffer.readu32(af,12))
else
buffer.copy(ah,0,af,0,ag)

for ai=ag,15,4 do
if ai+3<16 then
buffer.writeu32(ah,ai,0)
else
for aj=ai,15 do
buffer.writeu8(ah,aj,0)
end
break
end
end
end

return ah
end

function ae.Encrypt(af:buffer,ag:buffer):buffer
local ah=PadBuffer(af)
local ai=PrepareKey(ag)
local aj=GenerateKeySchedule(ai)

local ak=buffer.len(ah)
local al=buffer.create(ak)

EncryptBlocks(al,ah,aj,ak)
return al
end

function ae.Decrypt(af:buffer,ag:buffer):buffer
local ah=PrepareKey(ag)
local ai=GenerateKeySchedule(ah)

local aj=buffer.len(af)
local ak=buffer.create(aj)

DecryptBlocks(ak,af,ai,aj)
return UnpadBuffer(ak)
end

return ae end function a.F():typeof(__modImpl())local aa=a.cache.F if not aa then aa={c=__modImpl()}a.cache.F=aa end return aa.c end end do local function __modImpl()






















local aa={}

local function EncryptBlocks(ab:buffer,ac:buffer,ad:buffer,ae:number):()
for af=0,ae-1,8 do
local ag=buffer.readu32(ac,af)
local ah=buffer.readu32(ac,af+4)

local ai=buffer.readu32(ad,0)
local aj=buffer.readu32(ad,4)

ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)

for ak=0,27,4 do
aj=bit32.bxor(bit32.rrotate(aj,8)+ai,ak)
ai=bit32.bxor(bit32.lrotate(ai,3),aj)
ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)

aj=bit32.bxor(bit32.rrotate(aj,8)+ai,ak+1)
ai=bit32.bxor(bit32.lrotate(ai,3),aj)
ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)

aj=bit32.bxor(bit32.rrotate(aj,8)+ai,ak+2)
ai=bit32.bxor(bit32.lrotate(ai,3),aj)
ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)

aj=bit32.bxor(bit32.rrotate(aj,8)+ai,ak+3)
ai=bit32.bxor(bit32.lrotate(ai,3),aj)
ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)
end

aj=bit32.bxor(bit32.rrotate(aj,8)+ai,28)
ai=bit32.bxor(bit32.lrotate(ai,3),aj)
ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)

aj=bit32.bxor(bit32.rrotate(aj,8)+ai,29)
ai=bit32.bxor(bit32.lrotate(ai,3),aj)
ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)

aj=bit32.bxor(bit32.rrotate(aj,8)+ai,30)
ai=bit32.bxor(bit32.lrotate(ai,3),aj)
ah=bit32.bxor(bit32.rrotate(ah,8)+ag,ai)
ag=bit32.bxor(bit32.lrotate(ag,3),ah)

buffer.writeu32(ab,af,ag)
buffer.writeu32(ab,af+4,ah)
end
end

local function DecryptBlocks(ab:buffer,ac:buffer,ad:buffer,ae:number):()
for af=0,ae-1,8 do
local ag=buffer.readu32(ac,af)
local ah=buffer.readu32(ac,af+4)

for ai=27,0,-4 do
ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,(ai+4)*4))-ag,8)

ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,(ai+3)*4))-ag,8)

ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,(ai+2)*4))-ag,8)

ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,(ai+1)*4))-ag,8)
end

ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,12))-ag,8)

ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,8))-ag,8)

ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,4))-ag,8)

ag=bit32.rrotate(bit32.bxor(ag,ah),3)
ah=bit32.lrotate(bit32.bxor(ah,buffer.readu32(ad,0))-ag,8)

buffer.writeu32(ab,af,ag)
buffer.writeu32(ab,af+4,ah)
end
end

local function PadBuffer(ab:buffer):buffer
local ac=buffer.len(ab)
local ad=8-(ac%8)
local ae=buffer.create(ac+ad)

buffer.copy(ae,0,ab,0,ac)

if ad==8 then
buffer.writeu32(ae,ac,0x08080808)
buffer.writeu32(ae,ac+4,0x08080808)
elseif ad==4 then
buffer.writeu32(ae,ac,ad*0x01010101)
else
for af=ac,ac+ad-1 do
buffer.writeu8(ae,af,ad)
end
end

return ae
end

local function UnpadBuffer(ab:buffer):buffer
local ac=buffer.len(ab)
if ac==0 then
return ab
end

local ad=buffer.readu8(ab,ac-1)
local ae=buffer.create(ac-ad)
buffer.copy(ae,0,ab,0,ac-ad)

return ae
end

local function PadKey(ab:buffer):buffer
local ac=buffer.len(ab)
local ad=buffer.create(8)

if ac>=8 then
buffer.writeu32(ad,0,buffer.readu32(ab,0))
buffer.writeu32(ad,4,buffer.readu32(ab,4))
else
buffer.copy(ad,0,ab,0,ac)
for ae=ac,7 do
buffer.writeu8(ad,ae,0)
end
end

return ad
end

local function ExpandKey(ab:buffer):buffer
local ac=buffer.readu32(ab,0)
local ad=buffer.readu32(ab,4)

local ae=buffer.create(128)
buffer.writeu32(ae,0,ac)

for af=0,29,2 do
ad=bit32.bxor(bit32.rrotate(ad,8)+ac,af)
ac=bit32.bxor(bit32.lrotate(ac,3),ad)
buffer.writeu32(ae,(af+1)*4,ac)

ad=bit32.bxor(bit32.rrotate(ad,8)+ac,af+1)
ac=bit32.bxor(bit32.lrotate(ac,3),ad)
buffer.writeu32(ae,(af+2)*4,ac)
end

ad=bit32.bxor(bit32.rrotate(ad,8)+ac,30)
ac=bit32.bxor(bit32.lrotate(ac,3),ad)
buffer.writeu32(ae,124,ac)

return ae
end

function aa.Encrypt(ab:buffer,ac:buffer):buffer
local ad=PadBuffer(ab)
local ae=PadKey(ac)

local af=buffer.len(ad)
local ag=buffer.create(af)

EncryptBlocks(ag,ad,ae,af)
return ag
end

function aa.Decrypt(ab:buffer,ac:buffer):buffer
local ad=PadKey(ac)
local ae=buffer.len(ab)
local af=buffer.create(ae)

local ag=ExpandKey(ad)
DecryptBlocks(af,ab,ag,ae)
return UnpadBuffer(af)
end

return aa end function a.G():typeof(__modImpl())local aa=a.cache.G if not aa then aa={c=__modImpl()}a.cache.G=aa end return aa.c end end do local function __modImpl()


local aa=table.freeze{
AEAD=a.C(),
AES=a.D(),
XOR=a.E(),
Simon=a.F(),
Speck=a.G()
}

return aa end function a.H():typeof(__modImpl())local aa=a.cache.H if not aa then aa={c=__modImpl()}a.cache.H=aa end return aa.c end end do local function __modImpl()






















local aa=88
local ab=96

local ac={}

function ac.CarryWeak(ad:buffer,ae:buffer?):buffer
local af,ag,ah,ai,aj,ak,al,am,an,ao,ap=
buffer.readf64(ad,0),buffer.readf64(ad,8),
buffer.readf64(ad,16),buffer.readf64(ad,24),
buffer.readf64(ad,32),buffer.readf64(ad,40),
buffer.readf64(ad,48),buffer.readf64(ad,56),
buffer.readf64(ad,64),buffer.readf64(ad,72),
buffer.readf64(ad,80)

local aq=af+11333679558887148E7-11333679558887148E7;ag+=aq*5.9604644775390625E-8
local ar=ag+11333679558887148E7-11333679558887148E7;ah+=ar*5.9604644775390625E-8
local as=ah+11333679558887148E7-11333679558887148E7;ai+=as*5.9604644775390625E-8
local at=ai+11333679558887148E7-11333679558887148E7;aj+=at*5.9604644775390625E-8
local au=aj+11333679558887148E7-11333679558887148E7;ak+=au*5.9604644775390625E-8
local av=ak+11333679558887148E7-11333679558887148E7;al+=av*5.9604644775390625E-8
local aw=al+11333679558887148E7-11333679558887148E7;am+=aw*5.9604644775390625E-8
local ax=am+11333679558887148E7-11333679558887148E7;an+=ax*5.9604644775390625E-8
local ay=an+11333679558887148E7-11333679558887148E7;ao+=ay*5.9604644775390625E-8
local az=ao+11333679558887148E7-11333679558887148E7;ap+=az*5.9604644775390625E-8
local aA=ap+11333679558887148E7-11333679558887148E7

local aB=ae or buffer.create(ab)

buffer.writef64(aB,0,af-aq)
buffer.writef64(aB,8,ag-ar)
buffer.writef64(aB,16,ah-as)
buffer.writef64(aB,24,ai-at)
buffer.writef64(aB,32,aj-au)
buffer.writef64(aB,40,ak-av)
buffer.writef64(aB,48,al-aw)
buffer.writef64(aB,56,am-ax)
buffer.writef64(aB,64,an-ay)
buffer.writef64(aB,72,ao-az)
buffer.writef64(aB,80,ap-aA)
buffer.writef64(aB,88,aA*5.9604644775390625E-8)

return aB
end

function ac.Carry(ad:buffer,ae:buffer?):buffer
local af,ag,ah,ai,aj,ak,al,am,an,ao,ap=
buffer.readf64(ad,0),buffer.readf64(ad,8),
buffer.readf64(ad,16),buffer.readf64(ad,24),
buffer.readf64(ad,32),buffer.readf64(ad,40),
buffer.readf64(ad,48),buffer.readf64(ad,56),
buffer.readf64(ad,64),buffer.readf64(ad,72),
buffer.readf64(ad,80)

local aq=af%16777216;ag+=(af-aq)*5.9604644775390625E-8
local ar=ag%16777216;ah+=(ag-ar)*5.9604644775390625E-8
local as=ah%16777216;ai+=(ah-as)*5.9604644775390625E-8
local at=ai%16777216;aj+=(ai-at)*5.9604644775390625E-8
local au=aj%16777216;ak+=(aj-au)*5.9604644775390625E-8
local av=ak%16777216;al+=(ak-av)*5.9604644775390625E-8
local aw=al%16777216;am+=(al-aw)*5.9604644775390625E-8
local ax=am%16777216;an+=(am-ax)*5.9604644775390625E-8
local ay=an%16777216;ao+=(an-ay)*5.9604644775390625E-8
local az=ao%16777216;ap+=(ao-az)*5.9604644775390625E-8
local aA=ap%16777216

local aB=ae or buffer.create(ab)

buffer.writef64(aB,0,aq)
buffer.writef64(aB,8,ar)
buffer.writef64(aB,16,as)
buffer.writef64(aB,24,at)
buffer.writef64(aB,32,au)
buffer.writef64(aB,40,av)
buffer.writef64(aB,48,aw)
buffer.writef64(aB,56,ax)
buffer.writef64(aB,64,ay)
buffer.writef64(aB,72,az)
buffer.writef64(aB,80,aA)
buffer.writef64(aB,88,(ap-aA)*5.9604644775390625E-8)

return aB
end

function ac.Add(ad:buffer,ae:buffer,af:buffer?):buffer
local ag,ah,ai,aj,ak,al,am,an,ao,ap,aq=
buffer.readf64(ad,0),buffer.readf64(ad,8),
buffer.readf64(ad,16),buffer.readf64(ad,24),
buffer.readf64(ad,32),buffer.readf64(ad,40),
buffer.readf64(ad,48),buffer.readf64(ad,56),
buffer.readf64(ad,64),buffer.readf64(ad,72),
buffer.readf64(ad,80)

local ar,as,at,au,av,aw,ax,ay,az,aA,aB=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80)

local aC=af or buffer.create(ab)

buffer.writef64(aC,0,ag+ar)
buffer.writef64(aC,8,ah+as)
buffer.writef64(aC,16,ai+at)
buffer.writef64(aC,24,aj+au)
buffer.writef64(aC,32,ak+av)
buffer.writef64(aC,40,al+aw)
buffer.writef64(aC,48,am+ax)
buffer.writef64(aC,56,an+ay)
buffer.writef64(aC,64,ao+az)
buffer.writef64(aC,72,ap+aA)
buffer.writef64(aC,80,aq+aB)

return aC
end

function ac.Sub(ad:buffer,ae:buffer,af:buffer?):buffer
local ag,ah,ai,aj,ak,al,am,an,ao,ap,aq=
buffer.readf64(ad,0),buffer.readf64(ad,8),
buffer.readf64(ad,16),buffer.readf64(ad,24),
buffer.readf64(ad,32),buffer.readf64(ad,40),
buffer.readf64(ad,48),buffer.readf64(ad,56),
buffer.readf64(ad,64),buffer.readf64(ad,72),
buffer.readf64(ad,80)

local ar,as,at,au,av,aw,ax,ay,az,aA,aB=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80)

local aC=af or buffer.create(ab)

buffer.writef64(aC,0,ag-ar)
buffer.writef64(aC,8,ah-as)
buffer.writef64(aC,16,ai-at)
buffer.writef64(aC,24,aj-au)
buffer.writef64(aC,32,ak-av)
buffer.writef64(aC,40,al-aw)
buffer.writef64(aC,48,am-ax)
buffer.writef64(aC,56,an-ay)
buffer.writef64(aC,64,ao-az)
buffer.writef64(aC,72,ap-aA)
buffer.writef64(aC,80,aq-aB)

return aC
end

function ac.LMul(ad:buffer,ae:buffer,af:buffer?):buffer
local ag,ah,ai,aj,ak,al,am,an,ao,ap,aq=
buffer.readf64(ad,0),buffer.readf64(ad,8),
buffer.readf64(ad,16),buffer.readf64(ad,24),
buffer.readf64(ad,32),buffer.readf64(ad,40),
buffer.readf64(ad,48),buffer.readf64(ad,56),
buffer.readf64(ad,64),buffer.readf64(ad,72),
buffer.readf64(ad,80)

local ar,as,at,au,av,aw,ax,ay,az,aA,aB=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80)

local aC=af or buffer.create(ab)

buffer.writef64(aC,0,ag*ar)
buffer.writef64(aC,8,ah*ar+ag*as)
buffer.writef64(aC,16,ai*ar+ah*as+ag*at)
buffer.writef64(aC,24,aj*ar+ai*as+ah*at+ag*au)
buffer.writef64(aC,32,ak*ar+aj*as+ai*at+ah*au+ag*av)
buffer.writef64(aC,40,al*ar+ak*as+aj*at+ai*au+ah*av+ag*aw)
buffer.writef64(aC,48,am*ar+al*as+ak*at+aj*au+ai*av+ah*aw+ag*ax)
buffer.writef64(aC,56,an*ar+am*as+al*at+ak*au+aj*av+ai*aw+ah*ax+ag*ay)
buffer.writef64(aC,64,ao*ar+an*as+am*at+al*au+ak*av+aj*aw+ai*ax+ah*ay+ag*az)
buffer.writef64(aC,72,ap*ar+ao*as+an*at+am*au+al*av+ak*aw+aj*ax+ai*ay+ah*az+ag*aA)
buffer.writef64(aC,80,aq*ar+ap*as+ao*at+an*au+am*av+al*aw+ak*ax+aj*ay+ai*az+ah*aA+ag*aB)

return ac.Carry(aC,aC)
end

function ac.Mul(ad:buffer,ae:buffer,af:buffer?,ag:buffer?):(buffer,buffer)
local ah=ac.LMul(ad,ae,af)
local ai=buffer.readf64(ah,aa)

local aj,ak,al,am,an,ao,ap,aq,ar,as=
buffer.readf64(ad,8),buffer.readf64(ad,16),
buffer.readf64(ad,24),buffer.readf64(ad,32),
buffer.readf64(ad,40),buffer.readf64(ad,48),
buffer.readf64(ad,56),buffer.readf64(ad,64),
buffer.readf64(ad,72),buffer.readf64(ad,80)

local at,au,av,aw,ax,ay,az,aA,aB,aC=
buffer.readf64(ae,8),buffer.readf64(ae,16),
buffer.readf64(ae,24),buffer.readf64(ae,32),
buffer.readf64(ae,40),buffer.readf64(ae,48),
buffer.readf64(ae,56),buffer.readf64(ae,64),
buffer.readf64(ae,72),buffer.readf64(ae,80)

local aD=ag or buffer.create(ab)

buffer.writef64(aD,0,ai+as*at+ar*au+aq*av+ap*aw+ao*ax+an*ay+am*az+al*aA+ak*aB+aj*aC)
buffer.writef64(aD,8,as*au+ar*av+aq*aw+ap*ax+ao*ay+an*az+am*aA+al*aB+ak*aC)
buffer.writef64(aD,16,as*av+ar*aw+aq*ax+ap*ay+ao*az+an*aA+am*aB+al*aC)
buffer.writef64(aD,24,as*aw+ar*ax+aq*ay+ap*az+ao*aA+an*aB+am*aC)
buffer.writef64(aD,32,as*ax+ar*ay+aq*az+ap*aA+ao*aB+an*aC)
buffer.writef64(aD,40,as*ay+ar*az+aq*aA+ap*aB+ao*aC)
buffer.writef64(aD,48,as*az+ar*aA+aq*aB+ap*aC)
buffer.writef64(aD,56,as*aA+ar*aB+aq*aC)
buffer.writef64(aD,64,as*aB+ar*aC)
buffer.writef64(aD,72,as*aC)
buffer.writef64(aD,80,0)

return ah,ac.Carry(aD,aD)
end

function ac.DWAdd(ad:buffer,ae:buffer,af:buffer,ag:buffer,ah:buffer?,ai:buffer?):(buffer,buffer,number)
local aj=ac.Carry(ac.Add(ad,af,ah),ah)
local ak=buffer.readf64(aj,aa)

local al=ac.Add(ae,ag,ai)
buffer.writef64(al,0,buffer.readf64(al,0)+ak)
local am=ac.Carry(al,al)

return aj,am,buffer.readf64(am,aa)
end

function ac.Half(ad:buffer,ae:buffer?):buffer
local af,ag,ah,ai,aj,ak,al,am,an,ao,ap=
buffer.readf64(ad,0),
buffer.readf64(ad,8),
buffer.readf64(ad,16),
buffer.readf64(ad,24),
buffer.readf64(ad,32),
buffer.readf64(ad,40),
buffer.readf64(ad,48),
buffer.readf64(ad,56),
buffer.readf64(ad,64),
buffer.readf64(ad,72),
buffer.readf64(ad,80)

local aq=ae or buffer.create(ab)

buffer.writef64(aq,0,af*0.5+ag*8388608)
buffer.writef64(aq,8,ah*8388608)
buffer.writef64(aq,16,ai*8388608)
buffer.writef64(aq,24,aj*8388608)
buffer.writef64(aq,32,ak*8388608)
buffer.writef64(aq,40,al*8388608)
buffer.writef64(aq,48,am*8388608)
buffer.writef64(aq,56,an*8388608)
buffer.writef64(aq,64,ao*8388608)
buffer.writef64(aq,72,ap*8388608)
buffer.writef64(aq,80,0)

return ac.CarryWeak(aq,aq)
end

function ac.Third(ad:buffer,ae:buffer?):buffer
local af,ag,ah,ai,aj,ak,al,am,an,ao,ap=
buffer.readf64(ad,0),
buffer.readf64(ad,8),
buffer.readf64(ad,16),
buffer.readf64(ad,24),
buffer.readf64(ad,32),
buffer.readf64(ad,40),
buffer.readf64(ad,48),
buffer.readf64(ad,56),
buffer.readf64(ad,64),
buffer.readf64(ad,72),
buffer.readf64(ad,80)

local aq=af*0xaaaaaa
local ar=ag*0xaaaaaa+aq
local as=ah*0xaaaaaa+ar
local at=ai*0xaaaaaa+as
local au=aj*0xaaaaaa+at
local av=ak*0xaaaaaa+au
local aw=al*0xaaaaaa+av
local ax=am*0xaaaaaa+aw
local ay=an*0xaaaaaa+ax
local az=ao*0xaaaaaa+ay
local aA=ap*0xaaaaaa+az

local aB=ae or buffer.create(ab)

buffer.writef64(aB,0,af+aq)
buffer.writef64(aB,8,ag+ar)
buffer.writef64(aB,16,ah+as)
buffer.writef64(aB,24,ai+at)
buffer.writef64(aB,32,aj+au)
buffer.writef64(aB,40,ak+av)
buffer.writef64(aB,48,al+aw)
buffer.writef64(aB,56,am+ax)
buffer.writef64(aB,64,an+ay)
buffer.writef64(aB,72,ao+az)
buffer.writef64(aB,80,ap+aA)

return ac.CarryWeak(aB,aB)
end

function ac.Mod2(ad:buffer):number
return buffer.readf64(ad,0)%2
end

function ac.Mod3(ad:buffer):number
return(
buffer.readf64(ad,0)+
buffer.readf64(ad,8)+
buffer.readf64(ad,16)+
buffer.readf64(ad,24)+
buffer.readf64(ad,32)+
buffer.readf64(ad,40)+
buffer.readf64(ad,48)+
buffer.readf64(ad,56)+
buffer.readf64(ad,64)+
buffer.readf64(ad,72)+
buffer.readf64(ad,80)
)%3
end

function ac.Approx(ad:buffer):number
return buffer.readf64(ad,0)
+buffer.readf64(ad,8)*16777216
+buffer.readf64(ad,16)*281474976710656
+buffer.readf64(ad,24)*4722366482869645E6
+buffer.readf64(ad,32)*7922816251426434E13
+buffer.readf64(ad,40)*13292279957849158E20
+buffer.readf64(ad,48)*2230074519853062.5E28
+buffer.readf64(ad,56)*3.7414441915671115E50
+buffer.readf64(ad,64)*6.277101735386681E57
+buffer.readf64(ad,72)*1.0531229166855719E65
+buffer.readf64(ad,80)*1.7668470647783843E72
end

function ac.Cmp(ad:buffer,ae:buffer):number
return ac.Approx(ac.Sub(ad,ae))
end

function ac.Num(ad:number):buffer
local ae=buffer.create(ab)
buffer.writef64(ae,0,ad)

return ae
end

return ac end function a.I():typeof(__modImpl())local aa=a.cache.I if not aa then aa={c=__modImpl()}a.cache.I=aa end return aa.c end end do local function __modImpl()























local aa=a.I()

local ab=aa.Num(0)

local ac=buffer.create(8192)
local ad=buffer.create(8192)
local ae=buffer.create(96)
local af=buffer.create(96)
local ag=buffer.create(96)
local ah=buffer.create(32)

local ai=buffer.create(32)do
local aj={
0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
}
for ak=1,32 do
buffer.writeu8(ai,ak-1,aj[ak])
end
end

local aj=buffer.create(96)do
local ak=0

for al=0,9 do
local am=buffer.readu8(ai,ak)
+buffer.readu8(ai,ak+1)*256
+buffer.readu8(ai,ak+2)*65536

buffer.writef64(aj,al*8,am)
ak+=3
end

local al=buffer.readu8(ai,30)
+buffer.readu8(ai,31)*256
buffer.writef64(aj,80,al)
end

local ak=buffer.create(96)do
local al={
05537307,01942290,16765621,16628356,10618610,
07072433,03735459,01369940,15276086,13038191,
13409718
}
for am=1,11 do
buffer.writef64(ak,(am-1)*8,al[am])
end
end

local al=buffer.create(96)do
local am={
11711996,01747860,08326961,03814718,01859974,
13327461,16105061,07590423,04050668,08138906,
00000283
}
for an=1,11 do
buffer.writef64(al,(an-1)*8,am[an])
end
end

local am=buffer.create(96)do
local an={
5110253,3039345,2503500,11779568,15416472,
16766550,16777215,16777215,16777215,16777215,
4095
}
for ao=1,11 do
buffer.writef64(am,(ao-1)*8,an[ao])
end
end

local function Reduce(an:buffer):buffer
local ao=aa.Sub(an,aj)

if aa.Approx(ao)<0 then
return aa.Carry(an)
end

return aa.Carry(ao)
end

local function Demontgomery(an:buffer):buffer
local ao,ap=aa.Mul(aa.LMul(an,ak),aj)local
aq, ar=aa.DWAdd(an,ab,ao,ap)

return Reduce(ar)
end

local function RebaseLE(an:buffer,ao:number,ap:number,aq:number):(buffer,number)
local ar=0
local as=0
local at=1

for au=0,ao-1 do
as+=buffer.readf64(an,au*8)*at
at*=ap
while at>=aq do
local av=as%aq
as=(as-av)/aq
at/=aq
buffer.writef64(ac,ar*8,av)
ar+=1
end
end

if at>0 then
buffer.writef64(ac,ar*8,as)
ar+=1
end

return ac,ar
end

local an={}

function an.IsValidScalar(ao:buffer):boolean
local ap=ai
local aq=0

for ar=0,31 do
local as=buffer.readu8(ao,ar)
local at=buffer.readu8(ap,ar)
local au=as-at-aq
aq=1-bit32.rshift(au+256,8)
end

return aq==1
end

function an.Montgomery(ao:buffer):buffer
return an.Mul(ao,al)
end

function an.Add(ao:buffer,ap:buffer):buffer
return Reduce(aa.Add(ao,ap))
end

function an.Neg(ao:buffer):buffer
return Reduce(aa.Sub(aj,ao))
end

function an.Sub(ao:buffer,ap:buffer):buffer
return an.Add(ao,an.Neg(ap))
end

function an.Mul(ao:buffer,ap:buffer):buffer
local aq,ar=aa.Mul(ao,ap)
local as,at=aa.Mul(aa.LMul(aq,ak),aj)local
au, av=aa.DWAdd(aq,ar,as,at)

return Reduce(av)
end

function an.Encode(ao:buffer):buffer
local ap=Demontgomery(ao)
local aq=buffer.create(32)
local ar=0
for as=0,9 do
local at=buffer.readf64(ap,as*8)
buffer.writeu8(aq,ar,at%256)
at=at//256
buffer.writeu8(aq,ar+1,at%256)
at=at//256
buffer.writeu8(aq,ar+2,at%256)
ar+=3
end

local as=buffer.readf64(ap,80)
buffer.writeu8(aq,30,as%256)
as=as//256
buffer.writeu8(aq,31,as%256)

return aq
end

function an.Decode(ao:buffer):buffer
local ap=ag
local aq=0

for ar=0,9 do
local as=buffer.readu8(ao,aq)
+buffer.readu8(ao,aq+1)*256
+buffer.readu8(ao,aq+2)*65536

buffer.writef64(ap,ar*8,as)
aq+=3
end

local ar=buffer.readu8(ao,30)
+buffer.readu8(ao,31)*256
buffer.writef64(ap,80,ar)

return an.Montgomery(ap)
end

function an.DecodeWide(ao:buffer):buffer
local ap=ae
local aq=af

for ar=0,10 do
local as=ar*3
local at=buffer.readu8(ao,as)
+buffer.readu8(ao,as+1)*256
+buffer.readu8(ao,as+2)*65536
buffer.writef64(ap,ar*8,at)
end

for ar=0,9 do
local as=33+ar*3
local at=buffer.readu8(ao,as)
+buffer.readu8(ao,as+1)*256
+buffer.readu8(ao,as+2)*65536
buffer.writef64(aq,ar*8,at)
end
buffer.writef64(aq,80,buffer.readu8(ao,63))

local ar=an.Montgomery(ap)
local as=an.Montgomery(aq)
local at=an.Montgomery(as)

return an.Add(ar,at)
end

function an.DecodeClamped(ao:buffer):buffer
local ap=ah
buffer.copy(ap,0,ao,0,32)

local aq=buffer.readu8(ap,0)
buffer.writeu8(ap,0,bit32.band(aq,0xF8))

local ar=buffer.readu8(ap,31)
buffer.writeu8(ap,31,bit32.bor(bit32.band(ar,0x7F),0x40))

return an.Decode(ap)
end

function an.Eighth(ao:buffer):buffer
return an.Mul(ao,am)
end

function an.Bits(ao:buffer):(buffer,number)
local ap=Demontgomery(ao)
local aq,ar=RebaseLE(ap,11,16777216,2)

if ar>253 then
ar=253
end

return aq,ar
end

function an.MakeRuleset(ao:buffer,ap:buffer):(buffer,number,buffer,number)
local aq=Demontgomery(ao)
local ar=Demontgomery(ap)
local as=aa.Sub(aq,ar)

local at=aa.Mod2(aq)
local au=aa.Mod2(ar)

local av=aa.Mod3(aq)
local aw=aa.Mod3(ar)

local ax=aa.Approx(ar)
local ay=aa.Approx(as)

local az={[0]=0,2,1}

local aA=ad
local aB=0

while ay~=0 do
local aC=-1

if ay<0 then
aC=0
aq,ar=ar,aq
at,au=au,at
av,aw=aw,av
ax=aa.Approx(ar)
as=aa.Sub(aq,ar)
ay=-ay
elseif 4*ay<ax and av==az[aw]then
aC=1
aq,ar=aa.Third(aa.Add(aq,as)),aa.Third(aa.Sub(ar,as))::buffer
at,au=au,at
av,aw=aa.Mod3(aq),aa.Mod3(ar)
ax=aa.Approx(ar)
elseif 4*ay<ax and at==au and av==aw then
aC=2
aq=aa.Half(as)
at=aa.Mod2(aq)
av=az[(av-aw)%3]
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
elseif ay<3*ax then
aC=3
aq=aa.CarryWeak(as)
at=(at-au)%2
av=(av-aw)%3
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
elseif at==au then
aC=2
aq=aa.Half(as)
at=aa.Mod2(aq)
av=az[(av-aw)%3]
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
elseif at==0 then
aC=5
aq=aa.Half(aq)
at=aa.Mod2(aq)
av=az[av]
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
elseif av==0 then
aC=6
aq=aa.CarryWeak(aa.Sub(aa.Third(aq),ar))
at=(at-au)%2
av=aa.Mod3(aq)
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
elseif av==az[aw]then
aC=7
aq=aa.Third(aa.Sub(as,ar))
av=aa.Mod3(aq)
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
elseif av==aw then
aC=8
aq=aa.Third(as)
at=(at-au)%2
av=aa.Mod3(aq)
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
else
aC=9
ar=aa.Half(ar)
au=aa.Mod2(ar)
aw=az[aw]
ax=aa.Approx(ar)
as=aa.Sub(aq,ar)
ay=aa.Approx(as)
end

buffer.writef64(aA,aB*8,aC)
aB+=1
end

local aC,aD=RebaseLE(aq,11,16777216,2)
while aD>0 and buffer.readf64(aC,(aD-1)*8)==0 do
aD-=1
end

return aC,aD,aA,aB
end

return an end function a.J():typeof(__modImpl())local aa=a.cache.J if not aa then aa={c=__modImpl()}a.cache.J=aa end return aa.c end end do local function __modImpl()






















local aa=104
local ab=(3.281744050935889E-76)
local ac=buffer.create(aa)do
local ad={958640
,3467280121856
,14190305864170078E3
,1.9212800461602562E25
,5289485674109064E14
,6282208646924337E22
,6.209060889909311E44
,2.2396299431557287E50
,10617320669061486E41
,7697923713191456E47
,34592718286558492E53
,19681157917434908E60
,
}

for ae=1,12 do
buffer.writef64(ac,(ae-1)*8,ad[ae])
end
end

local ad={}

function ad.Num(ae:number):buffer
local af=buffer.create(aa)
buffer.writef64(af,0,ae)

return af
end

function ad.Neg(ae:buffer):buffer
local af,ag,ah,ai,aj,ak,al,am,an,ao,ap,aq=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80),buffer.readf64(ae,88)

local ar=buffer.create(aa)

buffer.writef64(ar,0,-af)
buffer.writef64(ar,8,-ag)
buffer.writef64(ar,16,-ah)
buffer.writef64(ar,24,-ai)
buffer.writef64(ar,32,-aj)
buffer.writef64(ar,40,-ak)
buffer.writef64(ar,48,-al)
buffer.writef64(ar,56,-am)
buffer.writef64(ar,64,-an)
buffer.writef64(ar,72,-ao)
buffer.writef64(ar,80,-ap)
buffer.writef64(ar,88,-aq)

return ar
end

function ad.Add(ae:buffer,af:buffer,ag:buffer?):buffer
local ah,ai,aj,ak,al,am,an,ao,ap,aq,ar,as=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80),buffer.readf64(ae,88)

local at,au,av,aw,ax,ay,az,aA,aB,aC,aD,aE=
buffer.readf64(af,0),buffer.readf64(af,8),
buffer.readf64(af,16),buffer.readf64(af,24),
buffer.readf64(af,32),buffer.readf64(af,40),
buffer.readf64(af,48),buffer.readf64(af,56),
buffer.readf64(af,64),buffer.readf64(af,72),
buffer.readf64(af,80),buffer.readf64(af,88)

local aF=ag or buffer.create(aa)

buffer.writef64(aF,0,ah+at)
buffer.writef64(aF,8,ai+au)
buffer.writef64(aF,16,aj+av)
buffer.writef64(aF,24,ak+aw)
buffer.writef64(aF,32,al+ax)
buffer.writef64(aF,40,am+ay)
buffer.writef64(aF,48,an+az)
buffer.writef64(aF,56,ao+aA)
buffer.writef64(aF,64,ap+aB)
buffer.writef64(aF,72,aq+aC)
buffer.writef64(aF,80,ar+aD)
buffer.writef64(aF,88,as+aE)

return aF
end

function ad.Sub(ae:buffer,af:buffer,ag:buffer?):buffer
local ah,ai,aj,ak,al,am,an,ao,ap,aq,ar,as=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80),buffer.readf64(ae,88)

local at,au,av,aw,ax,ay,az,aA,aB,aC,aD,aE=
buffer.readf64(af,0),buffer.readf64(af,8),
buffer.readf64(af,16),buffer.readf64(af,24),
buffer.readf64(af,32),buffer.readf64(af,40),
buffer.readf64(af,48),buffer.readf64(af,56),
buffer.readf64(af,64),buffer.readf64(af,72),
buffer.readf64(af,80),buffer.readf64(af,88)

local aF=ag or buffer.create(aa)

buffer.writef64(aF,0,ah-at)
buffer.writef64(aF,8,ai-au)
buffer.writef64(aF,16,aj-av)
buffer.writef64(aF,24,ak-aw)
buffer.writef64(aF,32,al-ax)
buffer.writef64(aF,40,am-ay)
buffer.writef64(aF,48,an-az)
buffer.writef64(aF,56,ao-aA)
buffer.writef64(aF,64,ap-aB)
buffer.writef64(aF,72,aq-aC)
buffer.writef64(aF,80,ar-aD)
buffer.writef64(aF,88,as-aE)

return aF
end

function ad.Carry(ae:buffer,af:buffer?):buffer
local ag,ah,ai,aj,ak,al,am,an,ao,ap,aq,ar=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80),buffer.readf64(ae,88)

local as,at,au,av,aw,ax,ay,az,aA,aB,aC,aD

aD=ar+3911109074562213.5E77-3911109074562213.5E77
ag+=3.281744050935889E-76*aD

as=ag+2833419889721787E7-2833419889721787E7
ah+=as
at=ah+5942112188569825E13-5942112188569825E13
ai+=at
au=ai+12461512460483586E19-12461512460483586E19
aj+=au
av=aj+2613368577952807.5E26-2613368577952807.5E26
ak+=av
aw=ak+10961262279981772E32-10961262279981772E32
al+=aw
ax=al+2.2987433112988333E54-2.2987433112988333E54
am+=ax
ay=am+4820814132776971E45-4820814132776971E45
an+=ay
az=an+1010998000018149E52-1010998000018149E52
ao+=az
aA=ao+4240432955468122.5E58-4240432955468122.5E58
ap+=aA
aB=ap+8892832453425884E64-8892832453425884E64
aq+=aB
aC=aq+18649621365367E73-18649621365367E73
ar=ar-aD+aC

aD=ar+3911109074562213.5E77-3911109074562213.5E77

local aE=af or buffer.create(aa)

buffer.writef64(aE,0,ag-as+3.281744050935889E-76*aD)
buffer.writef64(aE,8,ah-at)
buffer.writef64(aE,16,ai-au)
buffer.writef64(aE,24,aj-av)
buffer.writef64(aE,32,ak-aw)
buffer.writef64(aE,40,al-ax)
buffer.writef64(aE,48,am-ay)
buffer.writef64(aE,56,an-az)
buffer.writef64(aE,64,ao-aA)
buffer.writef64(aE,72,ap-aB)
buffer.writef64(aE,80,aq-aC)
buffer.writef64(aE,88,ar-aD)

return aE
end

function ad.Canonicalize(ae:buffer,af:buffer?):buffer
local ag,ah,ai,aj,ak,al,am,an,ao,ap,aq,ar=
buffer.readf64(ae,0),buffer.readf64(ae,8),
buffer.readf64(ae,16),buffer.readf64(ae,24),
buffer.readf64(ae,32),buffer.readf64(ae,40),
buffer.readf64(ae,48),buffer.readf64(ae,56),
buffer.readf64(ae,64),buffer.readf64(ae,72),
buffer.readf64(ae,80),buffer.readf64(ae,88)

local as,at,au,av,aw,ax,ay,az,aA,aB,aC,aD

as=ag%4194304
ah+=ag-as
at=ah%8796093022208
ai+=ah-at
au=ai%1.8446744073709552E19
aj+=ai-au
av=aj%38685626227668136E9
ak+=aj-av
aw=ak%1622592768292133.8E17
al+=ak-aw
ax=al%34028236692093850E22
am+=al-ax
ay=am%7136238463529800E29
an+=am-ay
az=an%14965776766268446E35
ao+=an-az
aA=ao%6.277101735386681E57
ap+=ao-aA
aB=ap%13164036458569648E48
aq+=ap-aB
aC=aq%2.7606985387162255E70
ar+=aq-aC
aD=ar%5789604461865810E61
as+=3.281744050935889E-76*(ar-aD)

local aE=af or buffer.create(aa)
if aD/2.7606985387162255E70==2097151
and aC/13164036458569648E48==2097151
and aB/6.277101735386681E57==2097151
and aA/14965776766268446E35==4194303
and az/7136238463529800E29==2097151
and ay/34028236692093850E22==2097151
and ax/1622592768292133.8E17==2097151
and aw/38685626227668136E9==4194303
and av/1.8446744073709552E19==2097151
and au/8796093022208==2097151
and at/4194304==2097151
and as>=4194285
then
buffer.writef64(aE,0,-4194285+as)
for aF=8,88,8 do
buffer.writef64(aE,aF,0)
end
else
buffer.writef64(aE,0,as)
buffer.writef64(aE,8,at)
buffer.writef64(aE,16,au)
buffer.writef64(aE,24,av)
buffer.writef64(aE,32,aw)
buffer.writef64(aE,40,ax)
buffer.writef64(aE,48,ay)
buffer.writef64(aE,56,az)
buffer.writef64(aE,64,aA)
buffer.writef64(aE,72,aB)
buffer.writef64(aE,80,aC)
buffer.writef64(aE,88,aD)
end

return aE
end

function ad.Eq(ae:buffer,af:buffer):boolean
local ag=ad.Canonicalize(ad.Sub(ae,af))
local ah=0
for ai=0,88,8 do
local aj=buffer.readu32(ag,ai)
local ak=buffer.readu32(ag,ai+4)
ah=bit32.bor(ah,aj,ak)
end

return ah==0
end

local ae:number,af:number,ag:number,ah:number,ai:number,aj:number,ak:number,
al:number,am:number,an:number,ao:number,ap:number
local aq:number,ar:number,as:number,at:number,au:number,av:number,aw:number,
ax:number,ay:number,az:number,aA:number,aB:number

function ad.Mul(aC:buffer,aD:buffer,aE:buffer?):buffer
local aF=ab
ae,af,ag,ah,ai,aj,ak,al,am,an,ao,ap=
buffer.readf64(aC,0),buffer.readf64(aC,8),
buffer.readf64(aC,16),buffer.readf64(aC,24),
buffer.readf64(aC,32),buffer.readf64(aC,40),
buffer.readf64(aC,48),buffer.readf64(aC,56),
buffer.readf64(aC,64),buffer.readf64(aC,72),
buffer.readf64(aC,80),buffer.readf64(aC,88)

aq,ar,as,at,au,av,aw,ax,ay,az,aA,aB=
buffer.readf64(aD,0),buffer.readf64(aD,8),
buffer.readf64(aD,16),buffer.readf64(aD,24),
buffer.readf64(aD,32),buffer.readf64(aD,40),
buffer.readf64(aD,48),buffer.readf64(aD,56),
buffer.readf64(aD,64),buffer.readf64(aD,72),
buffer.readf64(aD,80),buffer.readf64(aD,88)

local aG:number,aH:number,aI:number,aJ:number,aK:number,aL:number,b:number,
c:number,d:number,e:number,f:number,g:number=
ae,af,ag,ah,ai,aj,ak,al,am,an,ao,ap

local h:number,i:number,j:number,k:number,l:number,m:number,n:number,
o:number,p:number,q:number,r:number,s:number=
aq,ar,as,at,au,av,aw,ax,ay,az,aA,aB

local t=g*i
+f*j
+e*k
+d*l
+c*m
+b*n
+aL*o
+aK*p
+aJ*q
+aI*r
+aH*s

local u=g*j
+f*k
+e*l
+d*m
+c*n
+b*o
+aL*p
+aK*q
+aJ*r
+aI*s

local v=g*k
+f*l
+e*m
+d*n
+c*o
+b*p
+aL*q
+aK*r
+aJ*s

local w=g*l
+f*m
+e*n
+d*o
+c*p
+b*q
+aL*r
+aK*s

local x=g*m
+f*n
+e*o
+d*p
+c*q
+b*r
+aL*s

local y=g*n
+f*o
+e*p
+d*q
+c*r
+b*s

local z=g*o
+f*p
+e*q
+d*r
+c*s

local A=g*p
+f*q
+e*r
+d*s

local B=g*q
+f*r
+e*s

local C=g*r+f*s
local D=g*s

t*=aF
t+=aG*h

u*=aF
u+=aH*h
+aG*i

v*=aF
v+=aI*h
+aH*i
+aG*j

w*=aF
w+=aJ*h
+aI*i
+aH*j
+aG*k

x*=aF
x+=aK*h
+aJ*i
+aI*j
+aH*k
+aG*l

y*=aF
y+=aL*h
+aK*i
+aJ*j
+aI*k
+aH*l
+aG*m

z*=aF
z+=b*h
+aL*i
+aK*j
+aJ*k
+aI*l
+aH*m
+aG*n

A*=aF
A+=c*h
+b*i
+aL*j
+aK*k
+aJ*l
+aI*m
+aH*n
+aG*o

B*=aF
B+=d*h
+c*i
+b*j
+aL*k
+aK*l
+aJ*m
+aI*n
+aH*o
+aG*p

C*=aF
C+=e*h
+d*i
+c*j
+b*k
+aL*l
+aK*m
+aJ*n
+aI*o
+aH*p
+aG*q

D*=aF
D+=f*h
+e*i
+d*j
+c*k
+b*l
+aL*m
+aK*n
+aJ*o
+aI*p
+aH*q
+aG*r

local E=g*h
+f*i
+e*j
+d*k
+c*l
+b*m
+aL*n
+aK*o
+aJ*p
+aI*q
+aH*r
+aG*s

f=D+18649621365367E73-18649621365367E73
E+=f
g=E+3911109074562213.5E77-3911109074562213.5E77
t+=aF*g

aG=t+2833419889721787E7-2833419889721787E7
u+=aG
aH=u+5942112188569825E13-5942112188569825E13
v+=aH
aI=v+12461512460483586E19-12461512460483586E19
w+=aI
aJ=w+2613368577952807.5E26-2613368577952807.5E26
x+=aJ
aK=x+10961262279981772E32-10961262279981772E32
y+=aK
aL=y+2.2987433112988333E54-2.2987433112988333E54
z+=aL
b=z+4820814132776971E45-4820814132776971E45
A+=b
c=A+1010998000018149E52-1010998000018149E52
B+=c
d=B+4240432955468122.5E58-4240432955468122.5E58
C+=d
e=C+8892832453425884E64-8892832453425884E64
D=D-f+e
f=D+18649621365367E73-18649621365367E73
E=E-g+f

g=E+3911109074562213.5E77-3911109074562213.5E77

local F=aE or buffer.create(aa)

buffer.writef64(F,0,t-aG+aF*g)
buffer.writef64(F,8,u-aH)
buffer.writef64(F,16,v-aI)
buffer.writef64(F,24,w-aJ)
buffer.writef64(F,32,x-aK)
buffer.writef64(F,40,y-aL)
buffer.writef64(F,48,z-b)
buffer.writef64(F,56,A-c)
buffer.writef64(F,64,B-d)
buffer.writef64(F,72,C-e)
buffer.writef64(F,80,D-f)
buffer.writef64(F,88,E-g)

return F
end

function ad.Square(aC:buffer,aD:buffer?):buffer
local aE,aF,aG,aH,aI,aJ,aK,aL,b,c,d,e=
buffer.readf64(aC,0),buffer.readf64(aC,8),
buffer.readf64(aC,16),buffer.readf64(aC,24),
buffer.readf64(aC,32),buffer.readf64(aC,40),
buffer.readf64(aC,48),buffer.readf64(aC,56),
buffer.readf64(aC,64),buffer.readf64(aC,72),
buffer.readf64(aC,80),buffer.readf64(aC,88)

local f=aE*2
local g=aF*2
local h=aG*2
local i=aH*2
local j=aI*2
local k=aJ*2
local l=aK*2
local m=aL*2
local n=b*2
local o=c*2
local p=d*2

local q=3.281744050935889E-76

local r=e*g+d*h+c*i+b*j+aL*k+aK*aK
local s=e*h+d*i+c*j+b*k+aL*l
local t=e*i+d*j+c*k+b*l+aL*aL
local u=e*j+d*k+c*l+b*m
local v=e*k+d*l+c*m+b*b
local w=e*l+d*m+c*n
local x=e*m+d*n+c*c
local y=e*n+d*o
local z=e*o+d*d
local A=e*p
local B=e*e

local C=aE*aE
local D=aF*f
local E=aG*f+aF*aF
local F=aH*f+aG*g
local G=aI*f+aH*g+aG*aG
local H=aJ*f+aI*g+aH*h
local I=aK*f+aJ*g+aI*h+aH*aH
local J=aL*f+aK*g+aJ*h+aI*i
local K=b*f+aL*g+aK*h+aJ*i+aI*aI
local L=c*f+b*g+aL*h+aK*i+aJ*j
local M=d*f+c*g+b*h+aL*i+aK*j+aJ*aJ
local N=e*f+d*g+c*h+b*i+aL*j+aK*k

local O=aD or buffer.create(aa)
buffer.writef64(O,0,r*q+C)
buffer.writef64(O,8,s*q+D)
buffer.writef64(O,16,t*q+E)
buffer.writef64(O,24,u*q+F)
buffer.writef64(O,32,v*q+G)
buffer.writef64(O,40,w*q+H)
buffer.writef64(O,48,x*q+I)
buffer.writef64(O,56,y*q+J)
buffer.writef64(O,64,z*q+K)
buffer.writef64(O,72,A*q+L)
buffer.writef64(O,80,B*q+M)
buffer.writef64(O,88,N)

return ad.Carry(O,O)
end

function ad.KMul(aC:buffer,aD:number,aE:buffer?):buffer
local aF,aG,aH,aI,aJ,aK,aL,b,c,d,e,f=
buffer.readf64(aC,0),buffer.readf64(aC,8),
buffer.readf64(aC,16),buffer.readf64(aC,24),
buffer.readf64(aC,32),buffer.readf64(aC,40),
buffer.readf64(aC,48),buffer.readf64(aC,56),
buffer.readf64(aC,64),buffer.readf64(aC,72),
buffer.readf64(aC,80),buffer.readf64(aC,88)

local g,h,i,j,k,l,m,n,o,p,q,r

aF*=aD
aG*=aD
aH*=aD
aI*=aD
aJ*=aD
aK*=aD
aL*=aD
b*=aD
c*=aD
d*=aD
e*=aD
f*=aD

r=f+3911109074562213.5E77-3911109074562213.5E77
aF+=3.281744050935889E-76*r

g=aF+2833419889721787E7-2833419889721787E7
aG+=g
h=aG+5942112188569825E13-5942112188569825E13
aH+=h
i=aH+12461512460483586E19-12461512460483586E19
aI+=i
j=aI+2613368577952807.5E26-2613368577952807.5E26
aJ+=j
k=aJ+10961262279981772E32-10961262279981772E32
aK+=k
l=aK+2.2987433112988333E54-2.2987433112988333E54
aL+=l
m=aL+4820814132776971E45-4820814132776971E45
b+=m
n=b+1010998000018149E52-1010998000018149E52
c+=n
o=c+4240432955468122.5E58-4240432955468122.5E58
d+=o
p=d+8892832453425884E64-8892832453425884E64
e+=p
q=e+18649621365367E73-18649621365367E73
f=f-r+q

r=f+3911109074562213.5E77-3911109074562213.5E77

local s=aE or buffer.create(aa)

buffer.writef64(s,0,aF-g+3.281744050935889E-76*r)
buffer.writef64(s,8,aG-h)
buffer.writef64(s,16,aH-i)
buffer.writef64(s,24,aI-j)
buffer.writef64(s,32,aJ-k)
buffer.writef64(s,40,aK-l)
buffer.writef64(s,48,aL-m)
buffer.writef64(s,56,b-n)
buffer.writef64(s,64,c-o)
buffer.writef64(s,72,d-p)
buffer.writef64(s,80,e-q)
buffer.writef64(s,88,f-r)

return s
end

function ad.NSquare(aC:buffer,aD:number,aE:boolean?):buffer
local aF=ad.Square
if aE then
for aG=1,aD do
aF(aC,aC)
end

return aC
else
for aG=1,aD do
aC=aF(aC)
end

return aC
end
end

function ad.Invert(aC:buffer,aD:buffer?):buffer
local aE=ad.Mul

local aF=ad.Square(aC)
local aG=aE(aC,ad.NSquare(aF,2))
local aH=aE(aG,aF)

local aI=aE(ad.Square(aH),aG)
local aJ=aE(ad.NSquare(aI,5),aI)
local aK=aE(ad.NSquare(aJ,10),aJ)
local aL=aE(ad.NSquare(aK,20),aK)
local b=aE(ad.NSquare(aL,10),aJ)
local c=aE(ad.NSquare(b,50),b)
local d=aE(ad.NSquare(c,100),c)
local e=aE(ad.NSquare(d,50),b)

return aE(ad.NSquare(e,5),aH,aD)
end

function ad.SqrtDiv(aC:buffer,aD:buffer):buffer?
local aE=ad.Mul
local aF=ad.Square
local aG=ad.Carry

aG(aC,aC)

local aH=aF(aD)
local aI=aE(aD,aH)
local aJ=aE(aC,aI)
local aK=aF(aH)
local aL=aE(aJ,aK)

local b=aE(aF(aL),aL)
local c=aE(ad.NSquare(b,2),b)
local d=aE(ad.NSquare(c,4),c)
local e=aE(ad.NSquare(d,8),d)
local f=aE(ad.NSquare(e,2),b)
local g=aE(ad.NSquare(e,16),e)
local h=aE(ad.NSquare(g,18),f)
local i=aE(ad.NSquare(h,50),h)
local j=aE(ad.NSquare(i,100),i)
local k=aE(ad.NSquare(j,50),h)
local l=aE(ad.NSquare(k,2),aL)

local m=aE(aJ,l)
local n=aF(m)
local o=aE(aD,n)

if not ad.Eq(o,aC)then
m=aE(m,ac)
n=aF(m)
o=aE(aD,n)
end

if ad.Eq(o,aC)then
return m
else
return nil
end
end

function ad.Encode(aC:buffer):buffer
aC=ad.Canonicalize(aC)
local aD,aE,aF,aG,aH,aI,aJ,aK,aL,b,c,d=
buffer.readf64(aC,0),buffer.readf64(aC,8),
buffer.readf64(aC,16),buffer.readf64(aC,24),
buffer.readf64(aC,32),buffer.readf64(aC,40),
buffer.readf64(aC,48),buffer.readf64(aC,56),
buffer.readf64(aC,64),buffer.readf64(aC,72),
buffer.readf64(aC,80),buffer.readf64(aC,88)

local e=buffer.create(32)
local f=0
local g=aD

local h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

local i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

g+=aE/65536

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

local j=g%256
buffer.writeu8(e,f,j)
g=(g-j)/256
f+=1

g+=aF/1099511627776

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

j=g%256
buffer.writeu8(e,f,j)
g=(g-j)/256
f+=1

g+=aG/1.8446744073709552E19

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

g+=aH/12089258196146292E8

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

j=g%256
buffer.writeu8(e,f,j)
g=(g-j)/256
f+=1

g+=aI/20282409603651670E15

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

j=g%256
buffer.writeu8(e,f,j)
g=(g-j)/256
f+=1

g+=aJ/34028236692093850E22

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

g+=aK/2230074519853062.5E28

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

j=g%256
buffer.writeu8(e,f,j)
g=(g-j)/256
f+=1

g+=aL/3.7414441915671115E50

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

j=g%256
buffer.writeu8(e,f,j)
g=(g-j)/256
f+=1

g+=b/6.277101735386681E57

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

g+=c/4113761393303015E47

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

j=g%256
buffer.writeu8(e,f,j)
g=(g-j)/256
f+=1

g+=d/6.901746346790564E69

h=g%256
buffer.writeu8(e,f,h)
g=(g-h)/256
f+=1

i=g%256
buffer.writeu8(e,f,i)
g=(g-i)/256
f+=1

j=g%256
buffer.writeu8(e,f,j)

return e
end

function ad.Decode(aC:buffer):buffer
local aD,aE,aF=buffer.readu8(aC,0),buffer.readu8(aC,1),buffer.readu8(aC,2)
local aG=aD+aE*256+aF*65536

aD,aE,aF=buffer.readu8(aC,3),buffer.readu8(aC,4),buffer.readu8(aC,5)
local aH=aD+aE*256+aF*65536

local aI=buffer.readu16(aC,6)

aD,aE,aF=buffer.readu8(aC,8),buffer.readu8(aC,9),buffer.readu8(aC,10)
local aJ=aD+aE*256+aF*65536

aD,aE,aF=buffer.readu8(aC,11),buffer.readu8(aC,12),buffer.readu8(aC,13)
local aK=aD+aE*256+aF*65536

local aL=buffer.readu16(aC,14)

aD,aE,aF=buffer.readu8(aC,16),buffer.readu8(aC,17),buffer.readu8(aC,18)
local b=aD+aE*256+aF*65536

aD,aE,aF=buffer.readu8(aC,19),buffer.readu8(aC,20),buffer.readu8(aC,21)
local c=aD+aE*256+aF*65536

local d=buffer.readu16(aC,22)

aD,aE,aF=buffer.readu8(aC,24),buffer.readu8(aC,25),buffer.readu8(aC,26)
local e=aD+aE*256+aF*65536

aD,aE,aF=buffer.readu8(aC,27),buffer.readu8(aC,28),buffer.readu8(aC,29)
local f=aD+aE*256+aF*65536

local g=buffer.readu16(aC,30)%32768

local h=buffer.create(aa)

buffer.writef64(h,0,aG)
buffer.writef64(h,8,aH*16777216)
buffer.writef64(h,16,aI*281474976710656)
buffer.writef64(h,24,aJ*1.8446744073709552E19)
buffer.writef64(h,32,aK*30948500982134508E10)
buffer.writef64(h,40,aL*5192296858534828E18)
buffer.writef64(h,48,b*34028236692093850E22)
buffer.writef64(h,56,c*570899077082384E31)
buffer.writef64(h,64,d*9578097130411806E37)
buffer.writef64(h,72,e*6.277101735386681E57)
buffer.writef64(h,80,f*1.0531229166855719E65)
buffer.writef64(h,88,g*1.7668470647783843E72)

return ad.Carry(h,h)
end

function ad.Eqz(aC:buffer):boolean
local aD=ad.Canonicalize(aC)
local aE,aF,aG,aH,aI,aJ,aK,aL,b,c,d,e=
buffer.readf64(aD,0),buffer.readf64(aD,8),
buffer.readf64(aD,16),buffer.readf64(aD,24),
buffer.readf64(aD,32),buffer.readf64(aD,40),
buffer.readf64(aD,48),buffer.readf64(aD,56),
buffer.readf64(aD,64),buffer.readf64(aD,72),
buffer.readf64(aD,80),buffer.readf64(aD,88)

return aE+aF+aG+aH+aI+aJ+aK+aL+b+c+d+e==0
end

return ad end function a.K():typeof(__modImpl())local aa=a.cache.K if not aa then aa={c=__modImpl()}a.cache.K=aa end return aa.c end end do local function __modImpl()




local aa={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
0xca273ece,0xd186b8c7,0xeada7dd6,0xf57d4f7f,0x06f067aa,0x0a637dc5,0x113f9804,0x1b710b35,
0x28db77f5,0x32caab7b,0x3c9ebe0a,0x431d67c4,0x4cc5d4be,0x597f299c,0x5fcb6fab,0x6c44198c,
}

local ab={
0xd728ae22,0x23ef65cd,0xec4d3b2f,0x8189dbbc,0xf348b538,0xb605d019,0xaf194f9b,0xda6d8118,
0xa3030242,0x45706fbe,0x4ee4b28c,0xd5ffb4e2,0xf27b896f,0x3b1696b1,0x25c71235,0xcf692694,
0x9ef14ad2,0x384f25e3,0x8b8cd5b5,0x77ac9c65,0x592b0275,0x6ea6e483,0xbd41fbd4,0x831153b5,
0xee66dfab,0x2db43210,0x98fb213f,0xbeef0ee4,0x3da88fc2,0x930aa725,0xe003826f,0x0a0e6e70,
0x46d22ffc,0x5c26c926,0x5ac42aed,0x9d95b3df,0x8baf63de,0x3c77b2a8,0x47edaee6,0x1482353b,
0x4cf10364,0xbc423001,0xd0f89791,0x0654be30,0xd6ef5218,0x5565a910,0x5771202a,0x32bbd1b8,
0xb8d2d0c8,0x5141ab53,0xdf8eeb99,0xe19b48a8,0xc5c95a63,0xe3418acb,0x7763e373,0xd6b2b8a3,
0x5defb2fc,0x43172f60,0xa1f0ab72,0x1a6439ec,0x23631e28,0xde82bde9,0xb2c67915,0xe372532b,
0xea26619c,0x21c0c207,0xcde0eb1e,0xee6ed178,0x72176fba,0xa2c898a6,0xbef90dae,0x131c471b,
0x23047d84,0x40c72493,0x15c9bebc,0x9c100d4c,0xcb3e42b6,0xfc657e2a,0x3ad6faec,0x4a475817,
}

local ac=table.create(80)::{number}
local ad=table.create(80)::{number}
local ae=buffer.create(64)

local function PreProcess(af:buffer):(buffer,number)
local ag=buffer.len(af)
local ah=(128-((ag+17)%128))%128
local ai=ag+1+ah+16

local aj=buffer.create(ai)
buffer.copy(aj,0,af)
buffer.writeu8(aj,ag,0x80)
buffer.fill(aj,ag+1,0,ah+8)

local ak=ag*8
local al=ag+1+ah+8

for am=7,0,-1 do
buffer.writeu8(aj,al+am,ak%256)
ak=ak//256
end

return aj,ai
end

local function SHA512(af:buffer):buffer
local ag,ah=PreProcess(af)

local ai,aj=ac,ad
local ak,al=aa,ab

local am,an,ao,ap=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
local aq,ar,as,at=0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
local au,av,aw,ax=0xf3bcc908,0x84caa73b,0xfe94f82b,0x5f1d36f1
local ay,az,aA,aB=0xade682d1,0x2b3e6c1f,0xfb41bd6b,0x137e2179

for aC=0,ah-1,128 do
for aD=1,16 do
local aE=aC+(aD-1)*8
ai[aD]=bit32.byteswap(buffer.readu32(ag,aE))
aj[aD]=bit32.byteswap(buffer.readu32(ag,aE+4))
end

for aD=17,80 do
local aE,aF=ai[aD-15],aj[aD-15]
local aG,aH=ai[aD-2],aj[aD-2]

local aI=bit32.bxor(bit32.rshift(aF,1)+bit32.lshift(aE,31),bit32.rshift(aF,8)+bit32.lshift(aE,24),bit32.rshift(aF,7)+bit32.lshift(aE,25))
local aJ=bit32.bxor(bit32.rshift(aH,19)+bit32.lshift(aG,13),bit32.lshift(aH,3)+bit32.rshift(aG,29),bit32.rshift(aH,6)+bit32.lshift(aG,26))

local aK=aj[aD-16]+aI+aj[aD-7]+aJ
aj[aD]=bit32.bor(aK,0)
ai[aD]=bit32.bxor(bit32.rshift(aE,1)+bit32.lshift(aF,31),bit32.rshift(aE,8)+bit32.lshift(aF,24),bit32.rshift(aE,7))+
bit32.bxor(bit32.rshift(aG,19)+bit32.lshift(aH,13),bit32.lshift(aG,3)+bit32.rshift(aH,29),bit32.rshift(aG,6))+
ai[aD-16]+ai[aD-7]+aK//0x100000000
end

local aD,aE=am,au
local aF,aG=an,av
local aH,aI=ao,aw
local aJ,aK=ap,ax
local aL,b=aq,ay
local c,d=ar,az
local e,f=as,aA
local g,h=at,aB

for i=1,79,2 do
local j=bit32.bxor(bit32.rshift(b,14)+bit32.lshift(aL,18),bit32.rshift(b,18)+bit32.lshift(aL,14),bit32.lshift(b,23)+bit32.rshift(aL,9))
local k=bit32.bxor(bit32.rshift(aL,14)+bit32.lshift(b,18),bit32.rshift(aL,18)+bit32.lshift(b,14),bit32.lshift(aL,23)+bit32.rshift(b,9))
local l=bit32.bxor(bit32.rshift(aE,28)+bit32.lshift(aD,4),bit32.lshift(aE,30)+bit32.rshift(aD,2),bit32.lshift(aE,25)+bit32.rshift(aD,7))
local m=bit32.bxor(bit32.rshift(aD,28)+bit32.lshift(aE,4),bit32.lshift(aD,30)+bit32.rshift(aE,2),bit32.lshift(aD,25)+bit32.rshift(aE,7))
local n=bit32.band(b,d)+bit32.band(-1-b,f)
local o=bit32.band(aL,c)+bit32.band(-1-aL,e)
local p=bit32.band(aI,aG)+bit32.band(aE,bit32.bxor(aI,aG))
local q=bit32.band(aH,aF)+bit32.band(aD,bit32.bxor(aH,aF))

local r=h+j+n+al[i]+aj[i]
local s=g+k+o+ak[i]+ai[i]+r//0x100000000
r=bit32.bor(r,0)

g,h=e,f
e,f=c,d
c,d=aL,b

local t=aK+r
aL=aJ+s+t//0x100000000
b=bit32.bor(t,0)

aJ,aK=aH,aI
aH,aI=aF,aG
aF,aG=aD,aE

local u=r+l+p
aD=s+m+q+u//0x100000000
aE=bit32.bor(u,0)

local v=i+1
j=bit32.bxor(bit32.rshift(b,14)+bit32.lshift(aL,18),bit32.rshift(b,18)+bit32.lshift(aL,14),bit32.lshift(b,23)+bit32.rshift(aL,9))
k=bit32.bxor(bit32.rshift(aL,14)+bit32.lshift(b,18),bit32.rshift(aL,18)+bit32.lshift(b,14),bit32.lshift(aL,23)+bit32.rshift(b,9))
l=bit32.bxor(bit32.rshift(aE,28)+bit32.lshift(aD,4),bit32.lshift(aE,30)+bit32.rshift(aD,2),bit32.lshift(aE,25)+bit32.rshift(aD,7))
m=bit32.bxor(bit32.rshift(aD,28)+bit32.lshift(aE,4),bit32.lshift(aD,30)+bit32.rshift(aE,2),bit32.lshift(aD,25)+bit32.rshift(aE,7))
n=bit32.band(b,d)+bit32.band(-1-b,f)
o=bit32.band(aL,c)+bit32.band(-1-aL,e)
p=bit32.band(aI,aG)+bit32.band(aE,bit32.bxor(aI,aG))
q=bit32.band(aH,aF)+bit32.band(aD,bit32.bxor(aH,aF))

r=h+j+n+al[v]+aj[v]
s=g+k+o+ak[v]+ai[v]+r//0x100000000
r=bit32.bor(r,0)

g,h=e,f
e,f=c,d
c,d=aL,b

t=aK+r
aL=aJ+s+t//0x100000000
b=bit32.bor(t,0)

aJ,aK=aH,aI
aH,aI=aF,aG
aF,aG=aD,aE

u=r+l+p
aD=s+m+q+u//0x100000000
aE=bit32.bor(u,0)
end

au=au+aE
am=bit32.bor(am+aD+au//0x100000000,0)
au=bit32.bor(au,0)

av=av+aG
an=bit32.bor(an+aF+av//0x100000000,0)
av=bit32.bor(av,0)

aw=aw+aI
ao=bit32.bor(ao+aH+aw//0x100000000,0)
aw=bit32.bor(aw,0)

ax=ax+aK
ap=bit32.bor(ap+aJ+ax//0x100000000,0)
ax=bit32.bor(ax,0)

ay=ay+b
aq=bit32.bor(aq+aL+ay//0x100000000,0)
ay=bit32.bor(ay,0)

az=az+d
ar=bit32.bor(ar+c+az//0x100000000,0)
az=bit32.bor(az,0)

aA=aA+f
as=bit32.bor(as+e+aA//0x100000000,0)
aA=bit32.bor(aA,0)

aB=aB+h
at=bit32.bor(at+g+aB//0x100000000,0)
aB=bit32.bor(aB,0)
end

buffer.writeu32(ae,0,bit32.byteswap(am))
buffer.writeu32(ae,4,bit32.byteswap(au))
buffer.writeu32(ae,8,bit32.byteswap(an))
buffer.writeu32(ae,12,bit32.byteswap(av))
buffer.writeu32(ae,16,bit32.byteswap(ao))
buffer.writeu32(ae,20,bit32.byteswap(aw))
buffer.writeu32(ae,24,bit32.byteswap(ap))
buffer.writeu32(ae,28,bit32.byteswap(ax))
buffer.writeu32(ae,32,bit32.byteswap(aq))
buffer.writeu32(ae,36,bit32.byteswap(ay))
buffer.writeu32(ae,40,bit32.byteswap(ar))
buffer.writeu32(ae,44,bit32.byteswap(az))
buffer.writeu32(ae,48,bit32.byteswap(as))
buffer.writeu32(ae,52,bit32.byteswap(aA))
buffer.writeu32(ae,56,bit32.byteswap(at))
buffer.writeu32(ae,60,bit32.byteswap(aB))

return ae
end

return SHA512 end function a.L():typeof(__modImpl())local aa=a.cache.L if not aa then aa={c=__modImpl()}a.cache.L=aa end return aa.c end end do local function __modImpl()

























local aa=a.K()

local ab=416
local ac=104
local ad=312
local ae=6
local af=2^ae/2

local ag=aa.Mul(aa.Num(-121665),aa.Invert(aa.Num(121666)))
local ah=aa.KMul(ag,2)

local ai=buffer.create(ab)do
buffer.copy(ai,0,aa.Num(0),0,ac)
buffer.copy(ai,ac,aa.Num(1),0,ac)
buffer.copy(ai,2*ac,aa.Num(1),0,ac)
buffer.copy(ai,3*ac,aa.Num(0),0,ac)
end

local aj=buffer.create(ac)
local ak=buffer.create(ac)
local al=buffer.create(ac)
local am=buffer.create(ac)
local an=buffer.create(ac)
local ao=buffer.create(ac)
local ap=buffer.create(ac)
local aq=buffer.create(ac)

local ar=buffer.create(ab)
local as=buffer.create(ab)
local at=buffer.create(ac)
local au=buffer.create(ac)
local av=buffer.create(ac)
local aw=buffer.create(ac)
local ax=buffer.create(ac)
local ay=buffer.create(ac)
local az=buffer.create(ac)
local aA=buffer.create(ac)
local aB=buffer.create(ac)
local aC=buffer.create(ac)
local aD=buffer.create(ac)
local aE=buffer.create(ac)
local aF=buffer.create(ac)
local aG=buffer.create(ac)
local aH=buffer.create(ac)
local aI=buffer.create(ac)

local aJ=buffer.create(ab)
local aK=buffer.create(ad)
local aL=buffer.create(ab)
local b=buffer.create(ac)
local c=buffer.create(ac)
local d=buffer.create(ac)
local e=buffer.create(ac)
local f=buffer.create(ac)
local g=buffer.create(ac)
local h=buffer.create(ac)
local i=buffer.create(ac)

local j=buffer.create(ab)
local k=buffer.create(ac)
local l=buffer.create(ac)
local m=buffer.create(ac)
local n=buffer.create(ac)
local o=buffer.create(ac)
local p=buffer.create(ac)
local q=buffer.create(ac)
local r=buffer.create(ac)
local s=buffer.create(ac)
local t=buffer.create(ac)
local u=buffer.create(ac)
local v=buffer.create(ac)
local w=buffer.create(ac)

local x=buffer.create(4096)
local y=buffer.create(2176)

local z:buffer?
local A:buffer?

local function GetCoord(B:buffer,C:number,D:buffer?):buffer
local E=D or buffer.create(ac)
buffer.copy(E,0,B,C*ac,ac)
return E
end

local B={}

function B.Double(C:buffer,D:buffer?):buffer
local E=GetCoord(C,0,aj)
local F=GetCoord(C,1,ak)
local G=GetCoord(C,2,al)

local H=aa.Square(E)
local I=aa.Square(F)
aa.Square(G,G)
aa.Add(G,G,G)
local J=G
local K=aa.Add(H,I)
aa.Add(E,F,E)
local L=E
local M=aa.Square(L)
aa.Sub(M,K,M)
aa.Carry(M,M)
local N=M
aa.Sub(I,H,I)
local O=I
aa.Sub(J,O,J)
aa.Carry(J,J)
local P=J

local Q=aa.Mul(N,P)
local R=aa.Mul(O,K)
aa.Mul(P,O,P)
local S=P
aa.Mul(N,K,N)
local T=N

local U=D or buffer.create(ab)
buffer.copy(U,0*ac,Q,0,ac)
buffer.copy(U,1*ac,R,0,ac)
buffer.copy(U,2*ac,S,0,ac)
buffer.copy(U,3*ac,T,0,ac)

return U
end

function B.Add(C:buffer,D:buffer,E:buffer?):buffer
local F=GetCoord(C,0,aj)
local G=GetCoord(C,1,ak)
local H=GetCoord(C,2,al)
local I=GetCoord(C,3,am)

local J=GetCoord(D,0,an)
local K=GetCoord(D,1,ao)
local L=GetCoord(D,2,ap)
local M=GetCoord(D,3,aq)

local N=aa.Sub(G,F)
aa.Mul(N,K,N)
local O=N

local P=aa.Add(G,F)
aa.Mul(P,J,P)
local Q=P

aa.Mul(I,M,I)
local R=I

aa.Mul(H,L,H)
local S=H

local T=aa.Sub(Q,O)
local U=aa.Sub(S,R)

aa.Add(S,R,S)
local V=S

aa.Add(Q,O,Q)
local W=Q

local X=aa.Mul(T,U)
local Y=aa.Mul(V,W)
aa.Mul(U,V,U)
local Z=U
aa.Mul(T,W,T)
local _=T

local aM=E or buffer.create(ab)
buffer.copy(aM,0*ac,X,0,ac)
buffer.copy(aM,1*ac,Y,0,ac)
buffer.copy(aM,2*ac,Z,0,ac)
buffer.copy(aM,3*ac,_,0,ac)

return aM
end

function B.Sub(aM:buffer,C:buffer,D:buffer?):buffer
local E=GetCoord(aM,0,aj)
local F=GetCoord(aM,1,ak)
local G=GetCoord(aM,2,al)
local H=GetCoord(aM,3,am)

local I=GetCoord(C,0,an)
local J=GetCoord(C,1,ao)
local K=GetCoord(C,2,ap)
local L=GetCoord(C,3,aq)

local M=aa.Sub(F,E)
aa.Mul(M,I,M)
local N=M
aa.Add(F,E,F)
local O=F
aa.Mul(O,J,O)
local P=O
aa.Mul(H,L,H)
local Q=H
aa.Mul(G,K,G)
local R=G
local S=aa.Sub(P,N)
local T=aa.Add(R,Q)
local U=aa.Sub(R,Q)
aa.Add(P,N,P)
local V=P

local W=aa.Mul(S,T)
local X=aa.Mul(U,V)
aa.Mul(T,U,T)
local Y=T
aa.Mul(S,V,S)
local Z=S

local _=D or buffer.create(ab)
buffer.copy(_,0*ac,W,0,ac)
buffer.copy(_,1*ac,X,0,ac)
buffer.copy(_,2*ac,Y,0,ac)
buffer.copy(_,3*ac,Z,0,ac)

return _
end

function B.Niels(aM:buffer,C:buffer?):buffer
local D=GetCoord(aM,0,aj)
local E=GetCoord(aM,1,ak)
local F=GetCoord(aM,2,al)
local G=GetCoord(aM,3,am)

local H=aa.Add(E,D)
local I=aa.Sub(E,D)
aa.Add(F,F,F)
local J=F
aa.Mul(G,ah,G)
local K=G

local L=C or buffer.create(ab)
buffer.copy(L,0*ac,H,0,ac)
buffer.copy(L,1*ac,I,0,ac)
buffer.copy(L,2*ac,J,0,ac)
buffer.copy(L,3*ac,K,0,ac)

return L
end

function B.AffineNiels(aM:buffer,C:buffer?):buffer
local D=GetCoord(aM,0,aj)
local E=GetCoord(aM,1,ak)
local F=GetCoord(aM,3,am)

local G=aa.Add(E,D)
local H=aa.Sub(E,D)
aa.Mul(F,ah,F)
local I=F

local J=C or buffer.create(ad)
buffer.copy(J,0*ac,G,0,ac)
buffer.copy(J,1*ac,H,0,ac)
buffer.copy(J,2*ac,I,0,ac)

return J
end

function B.AddAffine(aM:buffer,C:buffer,D:buffer?):buffer
local E=GetCoord(aM,0,aj)
local F=GetCoord(aM,1,ak)
local G=GetCoord(aM,2,al)
local H=GetCoord(aM,3,am)

local I=GetCoord(C,0,an)
local J=GetCoord(C,1,ao)
local K=GetCoord(C,2,ap)

local L=aa.Sub(F,E)
aa.Mul(L,J,L)
local M=L

local N=aa.Add(F,E)
aa.Mul(N,I,N)
local O=N

aa.Mul(H,K,H)
local P=H

aa.Add(G,G,G)
local Q=G

local R=aa.Sub(O,M)
local S=aa.Sub(Q,P)

aa.Add(Q,P,Q)
local T=Q

aa.Add(O,M,O)
local U=O

local V=aa.Mul(R,S)
local W=aa.Mul(T,U)
aa.Mul(S,T,S)
local X=S
aa.Mul(R,U,R)
local Y=R

local Z=D or buffer.create(ab)
buffer.copy(Z,0*ac,V,0,ac)
buffer.copy(Z,1*ac,W,0,ac)
buffer.copy(Z,2*ac,X,0,ac)
buffer.copy(Z,3*ac,Y,0,ac)

return Z
end

function B.SubAffine(aM:buffer,C:buffer,D:buffer?):buffer
local E=GetCoord(aM,0,aj)
local F=GetCoord(aM,1,ak)
local G=GetCoord(aM,2,al)
local H=GetCoord(aM,3,am)

local I=GetCoord(C,0,an)
local J=GetCoord(C,1,ao)
local K=GetCoord(C,2,ap)

local L=aa.Sub(F,E)
aa.Mul(L,I,L)
local M=L

aa.Add(F,E,F)
local N=F
aa.Mul(N,J,N)
local O=N

aa.Mul(H,K,H)
local P=H

aa.Add(G,G,G)
local Q=G

local R=aa.Sub(O,M)
local S=aa.Add(Q,P)
local T=aa.Sub(Q,P)
aa.Add(O,M,O)
local U=O

local V=aa.Mul(R,S)
local W=aa.Mul(T,U)
aa.Mul(S,T,S)
local X=S
aa.Mul(R,U,R)
local Y=R

local Z=D or buffer.create(ab)
buffer.copy(Z,0*ac,V,0,ac)
buffer.copy(Z,1*ac,W,0,ac)
buffer.copy(Z,2*ac,X,0,ac)
buffer.copy(Z,3*ac,Y,0,ac)

return Z
end

function B.Scale(aM:buffer):buffer
local C=GetCoord(aM,0,aj)
local D=GetCoord(aM,1,ak)
local E=GetCoord(aM,2,al)

aa.Invert(E,E)
local F=E
aa.Mul(C,F,C)
local G=C
aa.Mul(D,F,D)
local H=D
local I=aa.Num(1)
local J=aa.Mul(G,H)

local K=buffer.create(ab)
buffer.copy(K,0*ac,G,0,ac)
buffer.copy(K,1*ac,H,0,ac)
buffer.copy(K,2*ac,I,0,ac)
buffer.copy(K,3*ac,J,0,ac)

return K
end

function B.Encode(aM:buffer):buffer
local C=B.Scale(aM)
local D=GetCoord(C,0,aj)
local E=GetCoord(C,1,ak)

local F=aa.Encode(E)
local G=aa.Canonicalize(D)
local H=buffer.readf64(G,0)%2

local I=buffer.create(32)
buffer.copy(I,0,F,0,32)

local J=buffer.readu8(I,31)
buffer.writeu8(I,31,J+H*128)

return I
end

function B.Decode(aM:buffer):buffer?
local C=buffer.create(32)
buffer.copy(C,0,aM,0,32)

local D=buffer.readu8(C,31)
local E=bit32.extract(D,7)
buffer.writeu8(C,31,bit32.band(D,0x7F))

local F=aa.Decode(C)
local G=aa.Square(F)
local H=aa.Sub(G,aa.Num(1))
local I=aa.Mul(G,ag)
local J=aa.Add(I,aa.Num(1))

local K=aa.SqrtDiv(H,J)
if not K then
return nil
end

local L=aa.Canonicalize(K)
local M=buffer.readf64(L,0)%2

if M~=E then
K=aa.Carry(aa.Neg(K))
end

local N=aa.Num(1)
local O=aa.Mul(K,F)

local P=buffer.create(ab)
buffer.copy(P,0*ac,K,0,ac)
buffer.copy(P,1*ac,F,0,ac)
buffer.copy(P,2*ac,N,0,ac)
buffer.copy(P,3*ac,O,0,ac)

return P
end

local aM=buffer.create(32)do
local C={
0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
}

for D=1,32 do
buffer.writeu8(aM,D-1,C[D])
end

z=B.Decode(aM)
end

function B.AffineRadixWTable(C:buffer,D:number):buffer
if D<=0 or D>8 then
error("Invalid Radix width",2)
end

if buffer.len(C)~=ab then
error("Invalid Basepoint",2)
end

local E=math.ceil(256/D)
local F=2^D/2

local G=buffer.create(E*F*ad)

local H=buffer.create(ab)
buffer.copy(H,0,C,0,ab)

local I=B.AffineNiels
local J=B.Add
local K=B.Double
local L=B.Scale
local M=B.Niels
local N=ad

for O=1,E do
local P=((O-1)*F*N)
local Q=buffer.create(ab)
buffer.copy(Q,0,H,0,ab)

local R=L(Q)
local S=I(R)
buffer.copy(G,P,S,0,N)

local T=M(R)

for U=2,F do
J(Q,T,Q)
local V=L(Q)
local W=I(V)

local X=P+((U-1)*N)
buffer.copy(G,X,W,0,N)
end

for U=1,D do
H=K(H)
end
end

return G
end

do
if z then
A=B.AffineRadixWTable(z,ae)
end
end

function B.GetAffineBasePointTableEntry(C:number,D:number,E:buffer?):buffer
if not A then
return buffer.create(0)
end

local F=((C-1)*af*ad)
local G=F+((D-1)*ad)

local H=E or buffer.create(ad)
buffer.copy(H,0,A,G,ad)

return H
end

function B.SignedRadixW(C:buffer,D:number,E:number):(buffer,number)
if D<=0 or D>256 then
error("Invalid scalar bit count",2)
end

if E<=0 or E>8 then
error("Invalid Radix width",2)
end

local F=2^E
local G=F/2
local H=272
local I=y
local J,K=0,0
local L=1

for M=1,D do
if M>D then
break
end

local N=buffer.readf64(C,(M-1)*8)
K+=N*L
L*=2

while M==D and K>0 or L>F do
if J>=H then
error"Output overflow in SignedRadixW"
end

local O=K%F
if O>=G then
O-=F
end
K=(K-O)/F
L/=F
buffer.writef64(I,J*8,O)
J+=1
end
end

return I,J
end

function B.WindowedNAF(C:buffer,D:number,E:number):(buffer,number)
local F=2^E
local G=F/2
local H=x
local I=0
local J=0
local K=1

for L=1,D do
local M=buffer.readf64(C,(L-1)*8)
J+=M*K
K*=2

while L==D and J>0 or K>F do
if J%2==0 then
J/=2
K/=2
buffer.writef64(H,I*8,0)
I+=1
else
local N=J%F
if N>=G then
N-=F
end
J-=N
buffer.writef64(H,I*8,N)
I+=1
end
end
end

while I>0 and buffer.readf64(H,(I-1)*8)==0 do
I-=1
end

return H,I
end

function B.WindowedNAFTable(C:buffer,D:number):buffer
local E=ab
local F=ac
local G=ah
local H=2^D

B.Double(C,j)

local I=buffer.create(H*E)

local J=aa.Add
local K=aa.Sub
local L=aa.Mul

local M=k
local N=l
local O=m
local P=n
local Q=o
local R=p
local S=q
local T=r
local U=s
local V=t
local W=u
local X=v
local Y=w
local Z=j

buffer.copy(M,0,Z,0,F)
buffer.copy(N,0,Z,F,F)
buffer.copy(O,0,Z,2*F,F)
buffer.copy(P,0,Z,3*F,F)

J(N,M,V)
K(N,M,W)
J(O,O,X)
L(P,G,Y)

buffer.copy(M,0,C,0,F)
buffer.copy(N,0,C,F,F)
buffer.copy(O,0,C,2*F,F)
buffer.copy(P,0,C,3*F,F)

J(N,M,Q)
K(N,M,R)
J(O,O,S)
L(P,G,T)

buffer.copy(I,0,Q,0,F)
buffer.copy(I,F,R,0,F)
buffer.copy(I,2*F,S,0,F)
buffer.copy(I,3*F,T,0,F)

buffer.copy(M,0,C,0,F)
buffer.copy(N,0,C,F,F)
buffer.copy(O,0,C,2*F,F)
buffer.copy(P,0,C,3*F,F)

for _=3,H,2 do
local aN=((_-1)*E)

K(N,M,U)
L(U,W,U)
J(N,M,Q)
L(Q,V,Q)
L(P,Y,P)
L(O,X,O)

K(Q,U,R)
K(O,P,S)
J(O,P,O)
J(Q,U,Q)

L(R,S,M)
L(O,Q,N)
L(S,O,O)
L(R,Q,P)

J(N,M,Q)
K(N,M,R)
J(O,O,S)
L(P,G,T)

buffer.copy(I,aN,Q,0,F)
buffer.copy(I,aN+F,R,0,F)
buffer.copy(I,aN+2*F,S,0,F)
buffer.copy(I,aN+3*F,T,0,F)
end

return I
end

function B.MulG(aN:buffer,C:number):buffer
local D=ab
local E=ac
local F=ad
local G=ai
local H=ae
local I=af
local J=A::buffer

local K,L=B.SignedRadixW(aN,C,H)

local M=aJ
buffer.copy(M,0,G,0,D)

local N=aK
local O=aL
buffer.copy(O,0,G,0,D)

local P=aa.Add
local Q=aa.Sub
local R=aa.Mul

local S=b
local T=c
local U=d
local V=e
local W=f
local X=g
local Y=h
local Z=i

for _=1,L do
local aO=buffer.readf64(K,(_-1)*8)

if aO>0 then
local aP=((_-1)*I*F)
local aQ=aP+((aO-1)*F)
buffer.copy(N,0,J,aQ,F)

buffer.copy(S,0,M,0,E)
buffer.copy(T,0,M,E,E)
buffer.copy(U,0,M,2*E,E)
buffer.copy(V,0,M,3*E,E)
buffer.copy(W,0,N,0,E)
buffer.copy(X,0,N,E,E)
buffer.copy(Y,0,N,2*E,E)

Q(T,S,Z)
R(Z,X,Z)
P(T,S,S)
R(S,W,S)
R(V,Y,V)
P(U,U,U)

Q(S,Z,T)
Q(U,V,W)
P(U,V,U)
P(S,Z,S)

R(T,W,Z)
R(U,S,V)
R(W,U,U)
R(T,S,S)

buffer.copy(M,0,Z,0,E)
buffer.copy(M,E,V,0,E)
buffer.copy(M,2*E,U,0,E)
buffer.copy(M,3*E,S,0,E)

elseif aO<0 then
local aP=((_-1)*I*F)
local aQ=aP+(((-aO)-1)*F)
buffer.copy(N,0,J,aQ,F)

buffer.copy(S,0,M,0,E)
buffer.copy(T,0,M,E,E)
buffer.copy(U,0,M,2*E,E)
buffer.copy(V,0,M,3*E,E)
buffer.copy(W,0,N,0,E)
buffer.copy(X,0,N,E,E)
buffer.copy(Y,0,N,2*E,E)

Q(T,S,Z)
R(Z,W,Z)
P(T,S,S)
R(S,X,S)
R(V,Y,V)
P(U,U,U)

Q(S,Z,T)
P(U,V,W)
Q(U,V,U)
P(S,Z,S)

R(T,W,Z)
R(U,S,V)
R(W,U,U)
R(T,S,S)

buffer.copy(M,0,Z,0,E)
buffer.copy(M,E,V,0,E)
buffer.copy(M,2*E,U,0,E)
buffer.copy(M,3*E,S,0,E)

else
local aP=((_-1)*I*F)
buffer.copy(N,0,J,aP,F)

buffer.copy(S,0,O,0,E)
buffer.copy(T,0,O,E,E)
buffer.copy(U,0,O,2*E,E)
buffer.copy(V,0,O,3*E,E)
buffer.copy(W,0,N,0,E)
buffer.copy(X,0,N,E,E)
buffer.copy(Y,0,N,2*E,E)

Q(T,S,Z)
R(Z,X,Z)
P(T,S,S)
R(S,W,S)
R(V,Y,V)
P(U,U,U)

Q(S,Z,T)
Q(U,V,W)
P(U,V,U)
P(S,Z,S)

R(T,W,Z)
R(U,S,V)
R(W,U,U)
R(T,S,S)

buffer.copy(O,0,Z,0,E)
buffer.copy(O,E,V,0,E)
buffer.copy(O,2*E,U,0,E)
buffer.copy(O,3*E,S,0,E)
end
end

local aO=buffer.create(D)
buffer.copy(aO,0,M,0,D)
return aO
end

function B.Mul(aN:buffer,aO:buffer,aP:number):buffer
local aQ=ab
local C=ac
local D=ai

local E,F=B.WindowedNAF(aO,aP,5)
local G=B.WindowedNAFTable(aN,5)

local H=ar
buffer.copy(H,0,D,0,aQ)

local I=as

local J=aa.Square
local K=aa.Add
local L=aa.Sub
local M=aa.Mul
local N=aa.Carry

local O=at
local P=au
local Q=av
local R=aw
local S=ax
local T=ay
local U=az

local V=aA
local W=aB
local X=aC
local Y=aD
local Z=aE
local _=aF
local aR=aG
local aS=aH
local aT=aI

for aU=F,1,-1 do
local aV=buffer.readf64(E,(aU-1)*8)

if aV==0 then
buffer.copy(O,0,H,0,C)
buffer.copy(P,0,H,C,C)
buffer.copy(Q,0,H,2*C,C)

J(O,R)
J(P,S)
J(Q,Q)
K(Q,Q,Q)
K(R,S,T)
K(O,P,O)
J(O,U)
L(U,T,U)
N(U,U)
L(S,R,S)
L(Q,S,Q)
N(Q,Q)

M(U,Q,O)
M(S,T,P)
M(Q,S,Q)
M(U,T,T)

buffer.copy(H,0,O,0,C)
buffer.copy(H,C,P,0,C)
buffer.copy(H,2*C,Q,0,C)
buffer.copy(H,3*C,T,0,C)

elseif aV>0 then
buffer.copy(I,0,G,((aV-1)*aQ),aQ)

buffer.copy(V,0,H,0,C)
buffer.copy(W,0,H,C,C)
buffer.copy(X,0,H,2*C,C)
buffer.copy(Y,0,H,3*C,C)
buffer.copy(Z,0,I,0,C)
buffer.copy(_,0,I,C,C)
buffer.copy(aR,0,I,2*C,C)
buffer.copy(aS,0,I,3*C,C)

L(W,V,aT)
M(aT,_,aT)
K(W,V,V)
M(V,Z,V)
M(Y,aS,Y)
M(X,aR,X)

L(V,aT,W)
L(X,Y,Z)
K(X,Y,X)
K(V,aT,V)

M(W,Z,aT)
M(X,V,Y)
M(Z,X,X)
M(W,V,V)

buffer.copy(H,0,aT,0,C)
buffer.copy(H,C,Y,0,C)
buffer.copy(H,2*C,X,0,C)
buffer.copy(H,3*C,V,0,C)

else
buffer.copy(I,0,G,(((-aV)-1)*aQ),aQ)

buffer.copy(V,0,H,0,C)
buffer.copy(W,0,H,C,C)
buffer.copy(X,0,H,2*C,C)
buffer.copy(Y,0,H,3*C,C)
buffer.copy(Z,0,I,0,C)
buffer.copy(_,0,I,C,C)
buffer.copy(aR,0,I,2*C,C)
buffer.copy(aS,0,I,3*C,C)

L(W,V,aT)
M(aT,Z,aT)
K(W,V,V)
M(V,_,V)
M(Y,aS,Y)
M(X,aR,X)

L(V,aT,W)
K(X,Y,Z)
L(X,Y,X)
K(V,aT,V)

M(W,Z,aT)
M(X,V,Y)
M(Z,X,X)
M(W,V,V)

buffer.copy(H,0,aT,0,C)
buffer.copy(H,C,Y,0,C)
buffer.copy(H,2*C,X,0,C)
buffer.copy(H,3*C,V,0,C)
end
end

local aU=buffer.create(aQ)
buffer.copy(aU,0,H,0,aQ)
return aU
end

return B end function a.M():typeof(__modImpl())local aa=a.cache.M if not aa then aa={c=__modImpl()}a.cache.M=aa end return aa.c end end do local function __modImpl()













local aa=buffer.create(512)do
local ab="0123456789abcdef"
for ac=0,255 do
local ad=bit32.rshift(ac,4)
local ae=ac%16

local af=string.byte(ab,ad+1)
local ag=string.byte(ab,ae+1)

local ah=af+bit32.lshift(ag,8)
buffer.writeu16(aa,ac*2,ah)
end
end

local ab=buffer.create(131072)do
for ac=0,255 do
for ad=0,255 do
local ae=0
local af=0

if ac>=48 and ac<=57 then
ae=ac-48
elseif ac>=65 and ac<=70 then
ae=ac-55
elseif ac>=97 and ac<=102 then
ae=ac-87
else
ae=0
end

if ad>=48 and ad<=57 then
af=ad-48
elseif ad>=65 and ad<=70 then
af=ad-55
elseif ad>=97 and ad<=102 then
af=ad-87
else
af=0
end

local ag=bit32.lshift(ae,4)+af
local ah=bit32.lshift(ad,8)+ac
buffer.writeu16(ab,ah*2,ag)
end
end
end

local ac={}

function ac.ToHex(ad:buffer):string
local ae=buffer.len(ad)
local af=buffer.create(ae*2)

local ag=aa

local ah=ae%8
local ai=0

for aj=0,ae-ah-1,8 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
local al=buffer.readu16(ag,buffer.readu8(ad,aj+1)*2)
local am=buffer.readu16(ag,buffer.readu8(ad,aj+2)*2)
local an=buffer.readu16(ag,buffer.readu8(ad,aj+3)*2)
local ao=buffer.readu16(ag,buffer.readu8(ad,aj+4)*2)
local ap=buffer.readu16(ag,buffer.readu8(ad,aj+5)*2)
local aq=buffer.readu16(ag,buffer.readu8(ad,aj+6)*2)
local ar=buffer.readu16(ag,buffer.readu8(ad,aj+7)*2)

buffer.writeu16(af,ai,ak)
buffer.writeu16(af,ai+2,al)
buffer.writeu16(af,ai+4,am)
buffer.writeu16(af,ai+6,an)
buffer.writeu16(af,ai+8,ao)
buffer.writeu16(af,ai+10,ap)
buffer.writeu16(af,ai+12,aq)
buffer.writeu16(af,ai+14,ar)

ai+=16
end

for aj=ae-ah,ae-1 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
buffer.writeu16(af,ai,ak)
ai+=2
end

return buffer.tostring(af)
end

function ac.FromHex(ad:string|buffer):buffer
local ae=if type(ad)=="string"then buffer.fromstring(ad)else ad
local af=buffer.len(ae)
if af%2~=0 then
error(`Length must be even, got {af}`)
end

local ag=buffer.create(bit32.rshift(af,1))
local ah=af%16
local ai=0
local aj=ab

for ak=0,af-ah-1,16 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(ae,ak+2)
local an=buffer.readu16(ae,ak+4)
local ao=buffer.readu16(ae,ak+6)
local ap=buffer.readu16(ae,ak+8)
local aq=buffer.readu16(ae,ak+10)
local ar=buffer.readu16(ae,ak+12)
local as=buffer.readu16(ae,ak+14)

local at=buffer.readu16(aj,al*2)
local au=buffer.readu16(aj,am*2)
local av=buffer.readu16(aj,an*2)
local aw=buffer.readu16(aj,ao*2)
local ax=buffer.readu16(aj,ap*2)
local ay=buffer.readu16(aj,aq*2)
local az=buffer.readu16(aj,ar*2)
local aA=buffer.readu16(aj,as*2)

local aB=bit32.lshift(aw,24)+bit32.lshift(av,16)+
bit32.lshift(au,8)+at
local aC=bit32.lshift(aA,24)+bit32.lshift(az,16)+
bit32.lshift(ay,8)+ax

buffer.writeu32(ag,ai,aB)
buffer.writeu32(ag,ai+4,aC)
ai+=8
end

for ak=af-ah,af-1,2 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(aj,al*2)
buffer.writeu8(ag,ai,am)
ai+=1
end

return ag
end

return ac end function a.N():typeof(__modImpl())local aa=a.cache.N if not aa then aa={c=__modImpl()}a.cache.N=aa end return aa.c end end do local function __modImpl()
























local aa=4
local ab=64
local ac=16

local ad=12
local ae=16
local af=32

local ag=buffer.create(16)do
local ah={string.byte("expand 32-byte k",1,-1)}
for ai,aj in ah do
buffer.writeu8(ag,ai-1,aj)
end
end

local ah=buffer.create(16)do
local ai={string.byte("expand 16-byte k",1,-1)}
for aj,ak in ai do
buffer.writeu8(ah,aj-1,ak)
end
end

local function ProcessBlock(ai:buffer,aj:number)
local ak:number,al:number,am:number,an:number,ao:number,ap:number,aq:number,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number=
buffer.readu32(ai,0),buffer.readu32(ai,4),
buffer.readu32(ai,8),buffer.readu32(ai,12),
buffer.readu32(ai,16),buffer.readu32(ai,20),
buffer.readu32(ai,24),buffer.readu32(ai,28),
buffer.readu32(ai,32),buffer.readu32(ai,36),
buffer.readu32(ai,40),buffer.readu32(ai,44),
buffer.readu32(ai,48),buffer.readu32(ai,52),
buffer.readu32(ai,56),buffer.readu32(ai,60)

for aA=1,aj do
local aB=aA%2==1

if aB then
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),16)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),12)
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),8)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),7)

al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),16)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),12)
al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),8)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),7)

am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),16)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),12)
am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),8)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),7)

an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),16)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),12)
an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),8)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),7)
else
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),16)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),12)
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),8)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),7)

al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),16)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),12)
al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),8)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),7)

am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),16)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),12)
am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),8)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),7)

an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),16)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),12)
an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),8)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),7)
end
end

buffer.writeu32(ai,0,buffer.readu32(ai,0)+ak)
buffer.writeu32(ai,4,buffer.readu32(ai,4)+al)
buffer.writeu32(ai,8,buffer.readu32(ai,8)+am)
buffer.writeu32(ai,12,buffer.readu32(ai,12)+an)
buffer.writeu32(ai,16,buffer.readu32(ai,16)+ao)
buffer.writeu32(ai,20,buffer.readu32(ai,20)+ap)
buffer.writeu32(ai,24,buffer.readu32(ai,24)+aq)
buffer.writeu32(ai,28,buffer.readu32(ai,28)+ar)
buffer.writeu32(ai,32,buffer.readu32(ai,32)+as)
buffer.writeu32(ai,36,buffer.readu32(ai,36)+at)
buffer.writeu32(ai,40,buffer.readu32(ai,40)+au)
buffer.writeu32(ai,44,buffer.readu32(ai,44)+av)
buffer.writeu32(ai,48,buffer.readu32(ai,48)+aw)
buffer.writeu32(ai,52,buffer.readu32(ai,52)+ax)
buffer.writeu32(ai,56,buffer.readu32(ai,56)+ay)
buffer.writeu32(ai,60,buffer.readu32(ai,60)+az)
end

local function InitializeState(ai:buffer,aj:buffer,ak:number):buffer
local al=buffer.len(ai)
local am=buffer.create(ac*aa)

local an=al==32 and ag or ah

buffer.copy(am,0,an,0,16)

buffer.copy(am,16,ai,0,math.min(al,16))
if al==32 then
buffer.copy(am,32,ai,16,16)
else
buffer.copy(am,32,ai,0,16)
end

buffer.writeu32(am,48,ak)
buffer.copy(am,52,aj,0,12)

return am
end

local function ChaCha20(ai:buffer,aj:buffer,ak:buffer,al:number?,am:number?):buffer
if ai==nil then
error("Data cannot be nil",2)
end

if typeof(ai)~="buffer"then
error(`Data must be a buffer, got {typeof(ai)}`,2)
end

if aj==nil then
error("Key cannot be nil",2)
end

if typeof(aj)~="buffer"then
error(`Key must be a buffer, got {typeof(aj)}`,2)
end

local an=buffer.len(aj)
if an~=ae and an~=af then
error(`Key must be {ae} or {af} bytes long, got {an} bytes`,2)
end

if ak==nil then
error("Nonce cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Nonce must be a buffer, got {typeof(ak)}`,2)
end

local ao=buffer.len(ak)
if ao~=ad then
error(`Nonce must be exactly {ad} bytes long, got {ao} bytes`,2)
end

if al then
if typeof(al)~="number"then
error(`Counter must be a number, got {typeof(al)}`,2)
end

if al<0 then
error(`Counter cannot be negative, got {al}`,2)
end

if al~=math.floor(al)then
error(`Counter must be an integer, got {al}`,2)
end

if al>=4294967296 then
error(`Counter must be less than 2^32, got {al}`,2)
end
end

if am then
if typeof(am)~="number"then
error(`Rounds must be a number, got {typeof(am)}`,2)
end

if am<=0 then
error(`Rounds must be positive, got {am}`,2)
end

if am~=math.floor(am)then
error(`Rounds must be an integer, got {am}`,2)
end

if am%2~=0 then
error(`Rounds must be even, got {am}`,2)
end
end

local ap=al or 1
local aq=am or 20

local ar=buffer.len(ai)
if ar==0 then
return buffer.create(0)
end

local as=buffer.create(ar)

local at=0

local au=InitializeState(aj,ak,ap)
local av=buffer.create(64)
buffer.copy(av,0,au,0)

while at<ar do
ProcessBlock(au,aq)

local aw=math.min(ab,ar-at)

for ax=0,aw-1 do
local ay=buffer.readu8(ai,at+ax)
local az=buffer.readu8(au,ax)
buffer.writeu8(as,at+ax,bit32.bxor(ay,az))
end

at+=aw
ap+=1
buffer.copy(au,0,av,0)
buffer.writeu32(au,48,ap)
end

return as
end

return ChaCha20 end function a.O():typeof(__modImpl())local aa=a.cache.O if not aa then aa={c=__modImpl()}a.cache.O=aa end return aa.c end end do local function __modImpl()




























local aa=64
local ab=32
local ac=64
local ad=64
local ae=ad*ab

local af=0x01
local ag=0x02
local ah=0x04
local ai=0x08

local aj=buffer.create(ab)do
local ak={
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
}
for al,am in ipairs(ak)do
buffer.writeu32(aj,(al-1)*4,am)
end
end

local function Compress(ak:buffer,al:buffer,am:number,an:number,ao:number,ap:boolean?):buffer
local aq=buffer.readu32(ak,0)
local ar=buffer.readu32(ak,4)
local as=buffer.readu32(ak,8)
local at=buffer.readu32(ak,12)
local au=buffer.readu32(ak,16)
local av=buffer.readu32(ak,20)
local aw=buffer.readu32(ak,24)
local ax=buffer.readu32(ak,28)

local ay,az,aA,aB=aq,ar,as,at
local aC,aD,aE,aF=au,av,aw,ax
local aG,aH,aI,aJ=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a

local aK=am%(4294967296)
local aL=(am-aK)*(2.3283064365386963E-10)

local aM=buffer.readu32(al,0)
local aN=buffer.readu32(al,4)
local aO=buffer.readu32(al,8)
local aP=buffer.readu32(al,12)
local aQ=buffer.readu32(al,16)
local aR=buffer.readu32(al,20)
local aS=buffer.readu32(al,24)
local aT=buffer.readu32(al,28)
local aU=buffer.readu32(al,32)
local aV=buffer.readu32(al,36)
local b=buffer.readu32(al,40)
local c=buffer.readu32(al,44)
local d=buffer.readu32(al,48)
local e=buffer.readu32(al,52)
local f=buffer.readu32(al,56)
local g=buffer.readu32(al,60)

local h
for i=1,7 do
ay+=aC+aM;aK=bit32.lrotate(bit32.bxor(aK,ay),16)
aG+=aK;aC=bit32.lrotate(bit32.bxor(aC,aG),20)
ay+=aC+aN;aK=bit32.lrotate(bit32.bxor(aK,ay),24)
aG+=aK;aC=bit32.lrotate(bit32.bxor(aC,aG),25)

az+=aD+aO;aL=bit32.lrotate(bit32.bxor(aL,az),16)
aH+=aL;aD=bit32.lrotate(bit32.bxor(aD,aH),20)
az+=aD+aP;aL=bit32.lrotate(bit32.bxor(aL,az),24)
aH+=aL;aD=bit32.lrotate(bit32.bxor(aD,aH),25)

aA+=aE+aQ;an=bit32.lrotate(bit32.bxor(an,aA),16)
aI+=an;aE=bit32.lrotate(bit32.bxor(aE,aI),20)
aA+=aE+aR;an=bit32.lrotate(bit32.bxor(an,aA),24)
aI+=an;aE=bit32.lrotate(bit32.bxor(aE,aI),25)

aB+=aF+aS;ao=bit32.lrotate(bit32.bxor(ao,aB),16)
aJ+=ao;aF=bit32.lrotate(bit32.bxor(aF,aJ),20)
aB+=aF+aT;ao=bit32.lrotate(bit32.bxor(ao,aB),24)
aJ+=ao;aF=bit32.lrotate(bit32.bxor(aF,aJ),25)

ay+=aD+aU;ao=bit32.lrotate(bit32.bxor(ao,ay),16)
aI+=ao;aD=bit32.lrotate(bit32.bxor(aD,aI),20)
ay+=aD+aV;ao=bit32.lrotate(bit32.bxor(ao,ay),24)
aI+=ao;aD=bit32.lrotate(bit32.bxor(aD,aI),25)

az+=aE+b;aK=bit32.lrotate(bit32.bxor(aK,az),16)
aJ+=aK;aE=bit32.lrotate(bit32.bxor(aE,aJ),20)
az+=aE+c;aK=bit32.lrotate(bit32.bxor(aK,az),24)
aJ+=aK;aE=bit32.lrotate(bit32.bxor(aE,aJ),25)

aA+=aF+d;aL=bit32.lrotate(bit32.bxor(aL,aA),16)
aG+=aL;aF=bit32.lrotate(bit32.bxor(aF,aG),20)
aA+=aF+e;aL=bit32.lrotate(bit32.bxor(aL,aA),24)
aG+=aL;aF=bit32.lrotate(bit32.bxor(aF,aG),25)

aB+=aC+f;an=bit32.lrotate(bit32.bxor(an,aB),16)
aH+=an;aC=bit32.lrotate(bit32.bxor(aC,aH),20)
aB+=aC+g;an=bit32.lrotate(bit32.bxor(an,aB),24)
aH+=an;aC=bit32.lrotate(bit32.bxor(aC,aH),25)

if i~=7 then
h=aO
aO=aP
aP=b
b=d
d=aV
aV=c
c=aR
aR=aM
aM=h

h=aS
aS=aQ
aQ=aT
aT=e
e=f
f=g
g=aU
aU=aN
aN=h
end
end

if ap then
local i=buffer.create(ac)
buffer.writeu32(i,0,bit32.bxor(ay,aG))
buffer.writeu32(i,4,bit32.bxor(az,aH))
buffer.writeu32(i,8,bit32.bxor(aA,aI))
buffer.writeu32(i,12,bit32.bxor(aB,aJ))
buffer.writeu32(i,16,bit32.bxor(aC,aK))
buffer.writeu32(i,20,bit32.bxor(aD,aL))
buffer.writeu32(i,24,bit32.bxor(aE,an))
buffer.writeu32(i,28,bit32.bxor(aF,ao))

buffer.writeu32(i,32,bit32.bxor(aG,aq))
buffer.writeu32(i,36,bit32.bxor(aH,ar))
buffer.writeu32(i,40,bit32.bxor(aI,as))
buffer.writeu32(i,44,bit32.bxor(aJ,at))
buffer.writeu32(i,48,bit32.bxor(aK,au))
buffer.writeu32(i,52,bit32.bxor(aL,av))
buffer.writeu32(i,56,bit32.bxor(an,aw))
buffer.writeu32(i,60,bit32.bxor(ao,ax))

return i
else
local i=buffer.create(ab)
buffer.writeu32(i,0,bit32.bxor(ay,aG))
buffer.writeu32(i,4,bit32.bxor(az,aH))
buffer.writeu32(i,8,bit32.bxor(aA,aI))
buffer.writeu32(i,12,bit32.bxor(aB,aJ))
buffer.writeu32(i,16,bit32.bxor(aC,aK))
buffer.writeu32(i,20,bit32.bxor(aD,aL))
buffer.writeu32(i,24,bit32.bxor(aE,an))
buffer.writeu32(i,28,bit32.bxor(aF,ao))

return i
end
end

local function ProcessMessage(ak:buffer,al:number,am:buffer,an:number):buffer
local ao=buffer.len(am)
local ap=buffer.create(ae)
local aq=0
local ar=buffer.create(ab)
buffer.copy(ar,0,ak,0,ab)

local as=0
local at=0
local au=0
local av=af

local aw=buffer.create(aa)

for ax=0,ao-aa-1,aa do
buffer.copy(aw,0,am,ax,aa)
local ay=al+av+au

ar=Compress(ar,aw,as,aa,ay)
av=0
at+=1

if at==15 then
au=ag
elseif at==16 then
local az=ar
local aA=as+1

while aA%2==0 do
aq=aq-1
local aB=buffer.create(ab)
buffer.copy(aB,0,ap,aq*ab,ab)

local aC=buffer.create(ac)
buffer.copy(aC,0,aB,0,ab)
buffer.copy(aC,ab,az,0,ab)

az=Compress(ak,aC,0,aa,al+ah)
aA=aA/2
end

buffer.copy(ap,aq*ab,az,0,ab)
aq=aq+1
buffer.copy(ar,0,ak,0,ab)
av=af

as+=1
at=0
au=0
end
end

local ax=ao==0 and 0 or((ao-1)%aa+1)
local ay=buffer.create(aa)

if ax>0 then
buffer.copy(ay,0,am,ao-ax,ax)
end

local az:buffer
local aA:buffer
local aB:number
local aC:number

if as>0 then
local aD=al+av+ag
local aE=Compress(ar,ay,as,ax,aD)

for aF=aq,2,-1 do
local aG=buffer.create(ab)
buffer.copy(aG,0,ap,(aF-1)*ab,ab)

local aH=buffer.create(ac)
buffer.copy(aH,0,aG,0,ab)
buffer.copy(aH,ab,aE,0,ab)

aE=Compress(ak,aH,0,aa,al+ah)
end

az=ak
local aF=buffer.create(ab)
buffer.copy(aF,0,ap,0,ab)

aA=buffer.create(ac)
buffer.copy(aA,0,aF,0,ab)
buffer.copy(aA,ab,aE,0,ab)

aB=aa
aC=al+ai+ah
else
az=ar
aA=ay
aB=ax
aC=al+av+ag+ai
end

local aD=buffer.create(an)
local aE=0

for aF=0,an//aa do
local aG=Compress(az,aA,aF,aB,aC,true)

local aH=math.min(aa,an-aE)
buffer.copy(aD,aE,aG,0,aH)
aE+=aH

if aE>=an then
break
end
end

return aD
end

return function(ak:buffer,al:number?):buffer
return ProcessMessage(aj,0,ak,al or 32)
end end function a.P():typeof(__modImpl())local aa=a.cache.P if not aa then aa={c=__modImpl()}a.cache.P=aa end return aa.c end end do local function __modImpl()


























local aa=a.N()
local ab=a.O()
local ac=a.P()


































local ad=64
local ae=32
local af=12

local ag:CSPRNGModule__DARKLUA_TYPE_f={
BlockExpansion=true,
SizeTarget=2048,
RekeyAfter=1024,

Key=buffer.create(0),
Nonce=buffer.create(0),
Buffer=buffer.create(0),

Counter=0,
BufferPosition=0,
BufferSize=0,
BytesLeft=0,

EntropyProviders={}
}::CSPRNGModule__DARKLUA_TYPE_f

local ah=buffer.create(ad)
local ai=math.max(math.floor(ag.RekeyAfter),2)
local aj=math.clamp(math.floor(ag.SizeTarget),64,4294967295)

local function Reset()
ag.Key=buffer.create(0)
ag.Nonce=buffer.create(0)
ag.Buffer=buffer.create(0)

ag.Counter=0
ag.BufferPosition=0
ag.BufferSize=0
end

local function GatherEntropy(ak:buffer?):number
local al=buffer.create(1024)
local am=0

local function WriteToBuffer(an:buffer)
local ao=buffer.len(an)
buffer.copy(al,am,an,0,ao)
am+=ao
end

local an=1.234
if tick then
an=tick()
local ao=buffer.create(8)
buffer.writef64(ao,0,an)
WriteToBuffer(ao)
end

local ao=os.clock()
local ap=buffer.create(8)
buffer.writef64(ap,0,ao)
WriteToBuffer(ap)

local aq=os.time()
local ar=buffer.create(8)
buffer.writeu32(ar,0,aq%0x100000000)
buffer.writeu32(ar,4,math.floor(aq/0x100000000))
WriteToBuffer(ar)

local as=5.678
if DateTime then
as=DateTime.now().UnixTimestampMillis
local at=buffer.create(8)
buffer.writef64(at,0,as)
WriteToBuffer(at)

local au=buffer.create(16)
buffer.writef32(au,0,as/1000)
buffer.writef32(au,4,(as%1000)/100)
buffer.writef32(au,8,as/86400000)
buffer.writef32(au,12,(as*0.001)%1)
WriteToBuffer(au)
else
WriteToBuffer(buffer.create(24))
end

local at=buffer.create(16)
buffer.writef32(at,0,ao/100)
buffer.writef32(at,4,an/1000)
buffer.writef32(at,8,(ao*12345.6789)%1)
buffer.writef32(at,12,(an*98765.4321)%1)
WriteToBuffer(at)

local au=buffer.create(32)
for av=0,7 do
local aw=math.noise(ao+av,aq+av,ao+aq+av)
local ax=math.noise(an+av*0.1,as*0.0001+av,ao*1.5+av)
local ay=math.noise(aq*0.01+av,ao+as*0.001,an+av*2)
local az=math.noise(as*0.00001+av,aq+ao+av,an*0.1+av)

buffer.writef32(au,av*4,aw+ax+ay+az)
end
WriteToBuffer(au)

local av=buffer.create(32)
for aw=0,7 do
local ax=os.clock()
local ay=0

local az=50+(aw*25)
for aA=1,az do
ay+=aA*aA+math.sin(aA/10)*math.cos(aA/7)
end

local aA=os.clock()
local aB=aA-ax
buffer.writef32(av,aw*4,aB*1000000)
end
WriteToBuffer(av)

local aw=buffer.create(24)
for ax=0,5 do
local ay=os.clock()

for az=1,20 do
buffer.create(64+az)
end

local az=os.clock()
buffer.writef32(aw,ax*4,(az-ay)*10000000)
end
WriteToBuffer(aw)

local ax=math.floor(an*1000000)
local ay=buffer.create(8)
buffer.writeu32(ay,0,ax%0x100000000)
buffer.writeu32(ay,4,math.floor(ax/0x100000000))
WriteToBuffer(ay)

if game then
if game.JobId and#game.JobId>0 then
local az=buffer.fromstring(game.JobId)
WriteToBuffer(az)
end

if game.PlaceId then
local az=buffer.create(8)
buffer.writeu32(az,0,game.PlaceId%0x100000000)
buffer.writeu32(az,4,math.floor(game.PlaceId/0x100000000))
WriteToBuffer(az)
end

if workspace and workspace.DistributedGameTime then
local az=buffer.create(8)
buffer.writef64(az,0,workspace.DistributedGameTime)
WriteToBuffer(az)

local aA=math.floor(workspace.DistributedGameTime*1000000)
local aB=buffer.create(8)
buffer.writeu32(aB,0,aA%0x100000000)
buffer.writeu32(aB,4,math.floor(aA/0x100000000))
WriteToBuffer(aB)
end
end

local az=buffer.create(128)
for aA=0,7 do
local aB={}
local aC=function()end
local aD=buffer.create(0)
local aE=newproxy()

local aF=string.gsub(tostring(aB),"table: ","")
local aG=string.gsub(tostring(aC),"function: ","")
local aH=string.gsub(tostring(aD),"buffer: ","")
local aI=string.gsub(tostring(aE),"userdata: ","")

local aJ=0
local aK=0
local aL=0
local aM=0
local aN=0

for aO=1,#aF do
aJ=bit32.bxor(aJ,string.byte(aF,aO))*31
end

if coroutine then
local aO=string.gsub(tostring(coroutine.create(function()end)),"thread: ","")
for aP=1,#aO do
aK=bit32.bxor(aK,string.byte(aO,aP))*31
end
end

for aO=1,#aG do
aL=bit32.bxor(aL,string.byte(aG,aO))*37
end
for aO=1,#aH do
aM=bit32.bxor(aM,string.byte(aH,aO))*41
end
for aO=1,#aI do
aN=bit32.bxor(aN,string.byte(aI,aO))*43
end

buffer.writeu32(az,aA*16,aJ)
buffer.writeu32(az,aA*16+4,aK)
buffer.writeu32(az,aA*16+8,aL)
buffer.writeu32(az,aA*16+12,bit32.bxor(aM,aN))
end
WriteToBuffer(az)

local function AddExtraEntropy(aA:buffer?,aB:boolean,aC:string?)
if not aA then
return
end

local aD=1024-am

if aD>0 then
local aE=buffer.len(aA)-aD
local aF=math.min(aD,buffer.len(aA))

if aE>0 and aB and aC then
warn(`CSPRNG: {aC} returned {aE} bytes more than available and was truncated to {aF} bytes`)
end

buffer.copy(al,am,aA,0,aF)
end
end

for aA,aB in ag.EntropyProviders do
local aC=1024-am
if aC>0 then
local aD:boolean,aE:buffer?=pcall(aB,aC)
if not aD then
warn(`CSPRNG Provider errored with {aE}`)
end

AddExtraEntropy(aE,true,`Entropy Provider #{aA}`)
end
end

if ak then
AddExtraEntropy(ak,false)
end

local aA=ac(al,ae+af)

ag.Key=buffer.create(ae)
buffer.copy(ag.Key,0,aA,0,ae)

ag.Nonce=buffer.create(af)
buffer.copy(ag.Nonce,0,aA,ae,af)

return buffer.len(al)-am
end

local function GenerateBlock()
buffer.fill(ah,0,0,ad)
local ak=ab(ah,ag.Key,ag.Nonce,ag.Counter,20)

ag.Buffer=if ag.BlockExpansion then ac(ak,aj)else ak
ag.BufferPosition=0
ag.BufferSize=buffer.len(ag.Buffer)
ag.Counter+=1

if ag.Counter%ai==0 then
GatherEntropy()
ag.Counter=0
end
end

local function GetBytes(ak:number):buffer
local al=buffer.create(ak)
local am=0

while am<ak do
if ag.BufferPosition>=ag.BufferSize then
GenerateBlock()
end

local an=ak-am
local ao=ag.BufferSize-ag.BufferPosition
local ap=math.min(an,ao)

buffer.copy(al,am,ag.Buffer,ag.BufferPosition,ap)
am+=ap
ag.BufferPosition+=ap
end

return al
end

local function GetFloat():number
if ag.BufferPosition+8>ag.BufferSize then
GenerateBlock()
end

local ak=buffer.readu32(ag.Buffer,ag.BufferPosition)
local al=buffer.readu32(ag.Buffer,ag.BufferPosition+4)
ag.BufferPosition+=8

local am=bit32.rshift(ak,5)
local an=bit32.rshift(al,6)

return(am*67108864.0+an)/9007199254740992.0
end

local function GetIntRange(ak:number,al:number):number
local am=al-ak+1
local an=0xFFFFFFFF
local ao=an-(an%am)

if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end

local ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4

if bit32.band(am,am-1)==0 then
return ak+bit32.band(ap,am-1)
else
while ap>ao do
if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end
ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4
end

return ak+(ap%am)
end
end

local function GetNumberRange(ak:number,al:number):number
if ak>al then
ak,al=al,ak
end

local am=al-ak
if am<=0 then
return ak
end

return ak+(GetFloat()*am)
end

local function GetRandomString(ak:number,al:boolean?):string|buffer
local am=buffer.create(ak)

for an=0,ak-1 do
buffer.writeu8(am,an,GetIntRange(36,122))
end

return if al
then am
else buffer.tostring(am)
end

local function GetEd25519RandomBytes():buffer
local ak=buffer.create(32)

for al=0,31 do
buffer.writeu8(ak,al,GetIntRange(0,255))
end

return ak
end

local function GetEd25519ClampedBytes(ak:buffer):buffer
local al=buffer.create(32)
buffer.copy(al,0,ak,0,32)

local am=buffer.readu8(al,0)
am=bit32.band(am,0xF8)
buffer.writeu8(al,0,am)

local an=buffer.readu8(al,31)
an=bit32.band(an,0x7F)
an=bit32.bor(an,0x40)
buffer.writeu8(al,31,an)

local ao=false
local ap=buffer.readu8(al,1)
for aq=2,30 do
if buffer.readu8(al,aq)~=ap then
ao=true
break
end
end

if not ao then
buffer.writeu8(al,15,bit32.bxor(ap,0x55))
end

return al
end

local function GetHexString(ak:number):string
local al=ak/2
local am=GetBytes(al)
local an=aa.ToHex(am)

return an
end

function ag.AddEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_e)
table.insert(ag.EntropyProviders,ak)
end

function ag.RemoveEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_e)
for al=#ag.EntropyProviders,1,-1 do
if ag.EntropyProviders[al]==ak then
table.remove(ag.EntropyProviders,al)
break
end
end
end

function ag.Random():number
return GetFloat()
end

function ag.RandomInt(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) can't be less than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=1
else
am=al
an=ak
end

return GetIntRange(an,am)
end

function ag.RandomNumber(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) must be bigger than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=0
else
am=al
an=ak
end

return GetNumberRange(an,am)
end

function ag.RandomBytes(ak:number):buffer
if type(ak)~="number"then
error(`Count must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Count must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Count must be an integer",2)
end

return GetBytes(ak)
end

function ag.RandomString(ak:number,al:boolean?):string|buffer
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if al~=nil and type(al)~="boolean"then
error(`AsBuffer must be a boolean or nil, got {typeof(al)}`,2)
end

return GetRandomString(ak,al)
end

function ag.RandomHex(ak:number):string
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if ak%2~=0 then
error(`Length must be even, got {ak}`,2)
end

return GetHexString(ak)
end

function ag.Ed25519ClampedBytes(ak:buffer):buffer
if type(ak)~="buffer"then
error(`Input must be a buffer, got {typeof(ak)}`,2)
end

return GetEd25519ClampedBytes(ak)
end

function ag.Ed25519Random():buffer
return GetEd25519ClampedBytes(GetEd25519RandomBytes())
end

function ag.Reseed(ak:buffer?)
if ak~=nil and type(ak)~="buffer"then
error(`CustomEntropy must be a buffer or nil, got {typeof(ak)}`,2)
end

Reset()
GatherEntropy(ak)
end

ag.BytesLeft=GatherEntropy()
GenerateBlock()

return ag end function a.Q():typeof(__modImpl())local aa=a.cache.Q if not aa then aa={c=__modImpl()}a.cache.Q=aa end return aa.c end end do local function __modImpl()























local aa=a.K()
local ab=a.Q()

local ac=208
local ad=104

local function GetMontgomeryCoord(ae:buffer,af:number):buffer
local ag=buffer.create(ad)
buffer.copy(ag,0,ae,af*ad,ad)

return ag
end

local function Double(ae:buffer):buffer
local af=GetMontgomeryCoord(ae,0)
local ag=GetMontgomeryCoord(ae,1)

local ah=aa.Add(af,ag)
local ai=aa.Square(ah)
local aj=aa.Sub(af,ag)
local ak=aa.Square(aj)
local al=aa.Sub(ai,ak)
local am=aa.Mul(ai,ak)
local an=aa.Mul(al,aa.Add(ak,aa.KMul(al,121666)))

local ao=buffer.create(ac)
buffer.copy(ao,0*ad,am,0,ad)
buffer.copy(ao,1*ad,an,0,ad)

return ao
end

local function LadderStep(ae:buffer,af:buffer,ag:buffer):(buffer,buffer)
local ah=GetMontgomeryCoord(ae,0)
local ai=GetMontgomeryCoord(ae,1)
local aj=GetMontgomeryCoord(af,0)
local ak=GetMontgomeryCoord(af,1)
local al=GetMontgomeryCoord(ag,0)
local am=GetMontgomeryCoord(ag,1)

local an=aa.Add(aj,ak)
local ao=aa.Square(an)
local ap=aa.Sub(aj,ak)
local aq=aa.Square(ap)

local ar=aa.Sub(ao,aq)
local as=aa.Sub(al,am)
local at=aa.Mul(as,an)
local au=aa.Add(al,am)
local av=aa.Mul(au,ap)

local aw=aa.Mul(ai,aa.Square(aa.Add(at,av)))
local ax=aa.Mul(ah,aa.Square(aa.Sub(at,av)))
local ay=aa.Mul(ao,aq)
local az=aa.Mul(ar,aa.Add(aq,aa.KMul(ar,121666)))

local aA=buffer.create(ac)
buffer.copy(aA,0*ad,ay,0,ad)
buffer.copy(aA,1*ad,az,0,ad)

local aB=buffer.create(ac)
buffer.copy(aB,0*ad,aw,0,ad)
buffer.copy(aB,1*ad,ax,0,ad)

return aA,aB
end

local function Ladder(ae:buffer,af:buffer,ag:number):buffer
local ah=buffer.create(ac)
buffer.copy(ah,0*ad,aa.Num(1),0,ad)
buffer.copy(ah,1*ad,aa.Num(0),0,ad)

local ai=buffer.create(ac)
buffer.copy(ai,0,ae,0,ac)

local aj=LadderStep

for ak=ag,1,-1 do
local al=buffer.readf64(af,(ak-1)*8)
if al==0 then
ah,ai=aj(ae,ah,ai)
else
ai,ah=aj(ae,ai,ah)
end
end

return ah
end

local ae={}

function ae.DifferentialAdd(af:buffer,ag:buffer,ah:buffer):buffer
local ai=GetMontgomeryCoord(af,0)
local aj=GetMontgomeryCoord(af,1)
local ak=GetMontgomeryCoord(ag,0)
local al=GetMontgomeryCoord(ag,1)
local am=GetMontgomeryCoord(ah,0)
local an=GetMontgomeryCoord(ah,1)

local ao=aa.Add(ak,al)
local ap=aa.Sub(ak,al)
local aq=aa.Add(am,an)
local ar=aa.Sub(am,an)
local as=aa.Mul(ar,ao)
local at=aa.Mul(aq,ap)

local au=aa.Mul(aj,aa.Square(aa.Add(as,at)))
local av=aa.Mul(ai,aa.Square(aa.Sub(as,at)))

local aw=buffer.create(ac)
buffer.copy(aw,0*ad,au,0,ad)
buffer.copy(aw,1*ad,av,0,ad)

return aw
end

function ae.Decode(af:buffer):buffer
local ag=buffer.create(ac)
buffer.copy(ag,0*ad,aa.Decode(af),0,ad)
buffer.copy(ag,1*ad,aa.Num(1),0,ad)

return ag
end

function ae.Prac(af:buffer,ag:{any}):(buffer?,buffer?,buffer?)
local ah=ae.DifferentialAdd
local ai=ab.Ed25519Random()
local aj=aa.Decode(ai)

local ak=GetMontgomeryCoord(af,0)
local al=GetMontgomeryCoord(af,1)
local am=buffer.create(ac)
buffer.copy(am,0*ad,aa.Mul(ak,aj),0,ad)
buffer.copy(am,1*ad,aa.Mul(al,aj),0,ad)

am=Double(Double(Double(am)))

local an=GetMontgomeryCoord(am,1)
if aa.Eqz(an)then
return nil,nil,nil
end

am=Ladder(am,ag[1],ag[2])

local ao:buffer=ag[3]
local ap:number=ag[4]
if ap==0 then
return am,nil,nil
end

local aq,ar
local as=buffer.readf64(ao,(ap-1)*8)
if as==2 then
local at=Double(am)
am,aq,ar=ah(am,at,am),am,at
elseif as==3 or as==5 then
am,aq,ar=Double(am),am,am
elseif as==6 then
local at=Double(am)
local au=ah(am,at,am)
am,aq,ar=Double(au),am,ah(am,au,at)
elseif as==7 then
local at=Double(am)
local au=ah(am,at,am)
local av=Double(at)
am,aq,ar=ah(au,av,am),am,av
elseif as==8 then
local at=Double(am)
local au=ah(am,at,am)
am,aq,ar=Double(at),am,au
else
am,aq,ar=am,Double(am),am
end

if not ar then
return nil,nil,nil
end

for at=ap-1,1,-1 do
local au=buffer.readf64(ao,(at-1)*8)
if au==0 then
am,aq=aq,am
elseif au==1 then
local av=ah(ar,am,aq)
am,aq=ah(aq,av,am),ah(am,av,aq)
elseif au==2 then
am,ar=ah(aq,ah(ar,am,aq),am),Double(am)
elseif au==3 then
am,ar=ah(ar,am,aq),am
elseif au==5 then
am,ar=Double(am),ah(aq,am,ar)
elseif au==6 then
local av=ah(ar,am,aq)
local aw=Double(av)
am,ar=ah(av,aw,av),ah(ah(am,av,aq),aw,am)
elseif au==7 then
local av=ah(ar,am,aq)
local aw=ah(aq,av,am)
am,ar=ah(am,aw,av),ah(av,aw,am)
elseif au==8 then
local av=Double(am)
am,ar=ah(ar,av,ah(ar,am,aq)),ah(am,av,am)
else
aq,ar=Double(aq),ah(am,ar,aq)
end
end

return am,aq,ar
end

local af=buffer.create(ac)
buffer.copy(af,0*ad,aa.Num(9),0,ad)
buffer.copy(af,1*ad,aa.Num(1),0,ad)
ae.G=af

return ae end function a.R():typeof(__modImpl())local aa=a.cache.R if not aa then aa={c=__modImpl()}a.cache.R=aa end return aa.c end end do local function __modImpl()

























local aa=a.J()
local ab=a.K()
local ac=a.R()
local ad=a.L()
local ae=a.Q()

local af=104

local ag=32
local ah=32
local ai=64

local aj=32

local ak={}

function ak.Mask(al:buffer):buffer
if al==nil then
error("SecretKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`SecretKey must be a buffer, got {typeof(al)}`,2)
end

local am=buffer.len(al)
if am~=ag then
error(`SecretKey must be exactly {ag} bytes long, got {am} bytes`,2)
end

local an=ae.Ed25519Random()
local ao=aa.DecodeClamped(al)
local ap=aa.DecodeClamped(an)
local aq=aa.Sub(ao,ap)
local ar=aa.Encode(aq)

local as=buffer.create(64)
buffer.copy(as,0,ar,0,32)
buffer.copy(as,32,an,0,32)

return as
end

function ak.MaskSignature(al:buffer):buffer
if al==nil then
error("SignatureSecretKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`SignatureSecretKey must be a buffer, got {typeof(al)}`,2)
end

local am=buffer.len(al)
if am~=aj then
error(`SignatureSecretKey must be exactly {aj} bytes long, got {am} bytes`,2)
end

local an=ad(al)
local ao=buffer.create(32)
buffer.copy(ao,0,an,0,32)

return ak.Mask(ao)
end

function ak.Remask(al:buffer):buffer
if al==nil then
error("MaskedKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`MaskedKey must be a buffer, got {typeof(al)}`,2)
end

local am=buffer.len(al)
if am~=ai then
error(`MaskedKey must be exactly {ai} bytes long, got {am} bytes`,2)
end

local an=ae.Ed25519Random()

local ao=buffer.create(32)
buffer.copy(ao,0,al,0,32)
local ap=aa.Decode(ao)

local aq=buffer.create(32)
buffer.copy(aq,0,al,32,32)
local ar=aa.DecodeClamped(aq)

local as=aa.DecodeClamped(an)
local at=aa.Add(ap,aa.Sub(ar,as))
local au=aa.Encode(at)

local av=buffer.create(64)
buffer.copy(av,0,au,0,32)
buffer.copy(av,32,an,0,32)

return av
end

function ak.MaskComponent(al:buffer):buffer
if al==nil then
error("MaskedKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`MaskedKey must be a buffer, got {typeof(al)}`,2)
end

local am=buffer.len(al)
if am~=ai then
error(`MaskedKey must be exactly {ai} bytes long, got {am} bytes`,2)
end

local an=buffer.create(32)
buffer.copy(an,0,al,32,32)

return an
end

local function ExchangeOnPoint(al:buffer,am:buffer):(buffer,buffer)
local an=buffer.create(32)
buffer.copy(an,0,al,0,32)
local ao=aa.Decode(an)

local ap=buffer.create(32)
buffer.copy(ap,0,al,32,32)
local aq=aa.DecodeClamped(ap)

local ar,as,at=ac.Prac(am,{aa.MakeRuleset(aa.Eighth(aq),aa.Eighth(ao))})
if not ar then
error("Invalid public key",2)
end

if not at or not as then
error("Invalid public key",2)
end

local au=ac.DifferentialAdd(at,ar,as)

local av=buffer.create(af)
buffer.copy(av,0,am,0*af,af)
local aw=buffer.create(af)
buffer.copy(aw,0,am,1*af,af)

local ax=buffer.create(af)
buffer.copy(ax,0,au,0*af,af)
local ay=buffer.create(af)
buffer.copy(ay,0,au,1*af,af)

local az=buffer.create(af)
buffer.copy(az,0,ar,0*af,af)
local aA=buffer.create(af)
buffer.copy(aA,0,ar,1*af,af)

av,aw=ab.Mul(av,aw),ab.Square(aw)::buffer
ax,ay=ab.Mul(ax,ay),ab.Square(ay)::buffer
az,aA=ab.Mul(az,aA),ab.Square(aA)::buffer

local aB=ab.Square(av)
local aC=ab.Square(aw)
local aD=ab.Mul(av,aw)
local aE=ab.KMul(aD,486662)
local aF=ab.Mul(av,ab.Add(aB,ab.Carry(ab.Add(aE,aC))))

local aG=ab.SqrtDiv(ab.Num(1),ab.Mul(ab.Mul(ay,aA),aF))
if not aG then
error("Invalid public key",2)
end

local aH=ab.Mul(ab.Square(aG),aF)
local aI=ab.Mul(aH,aA)
local aJ=ab.Mul(aH,ay)

return ab.Encode(ab.Mul(ax,aI)),ab.Encode(ab.Mul(az,aJ))
end

function ak.PublicKey(al:buffer):buffer
if al==nil then
error("MaskedKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`MaskedKey must be a buffer, got {typeof(al)}`,2)
end

local am=buffer.len(al)
if am~=ai then
error(`MaskedKey must be exactly {ai} bytes long, got {am} bytes`,2)
end

return(ExchangeOnPoint(al,ac.G))
end

function ak.Exchange(al:buffer,am:buffer):(buffer,buffer)
if al==nil then
error("MaskedSecretKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`MaskedSecretKey must be a buffer, got {typeof(al)}`,2)
end

local an=buffer.len(al)
if an~=ai then
error(`MaskedSecretKey must be exactly {ai} bytes long, got {an} bytes`,2)
end

if am==nil then
error("TheirPublicKey cannot be nil",2)
end

if typeof(am)~="buffer"then
error(`TheirPublicKey must be a buffer, got {typeof(am)}`,2)
end

local ao=buffer.len(am)
if ao~=ah then
error(`TheirPublicKey must be exactly {ah} bytes long, got {ao} bytes`,2)
end

return ExchangeOnPoint(al,ac.Decode(am))
end

return ak end function a.S():typeof(__modImpl())local aa=a.cache.S if not aa then aa={c=__modImpl()}a.cache.S=aa end return aa.c end end do local function __modImpl()































local aa=a.J()
local ab=a.K()
local ac=a.L()
local ad=a.M()
local ae=a.S()
local af=a.Q()

local ag=32
local ah=32
local ai=64

local function ConcatBuffers(...):buffer
local aj={...}
local ak=0

for al,am in aj do
ak+=buffer.len(am)
end

local al=buffer.create(ak)
local am=0

for an,ao in aj do
local ap=buffer.len(ao)
buffer.copy(al,am,ao,0,ap)
am+=ap
end

return al
end







local aj={
CSPRNG=af,
X25519=ae
}

function aj.PublicKey(ak:buffer):buffer
if ak==nil then
error("SecretKey cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`SecretKey must be a buffer, got {typeof(ak)}`,2)
end

local al=buffer.len(ak)
if al~=ag then
error(`SecretKey must be exactly {ag} bytes long, got {al} bytes`,2)
end

local am=ac(ak)
local an=buffer.create(32)
buffer.copy(an,0,am,0,32)

local ao=aa.DecodeClamped(an)
local ap,aq=aa.Bits(ao)

return ad.Encode(ad.MulG(ap,aq))
end

function aj.Sign(ak:buffer,al:buffer,am:buffer):buffer
if al==nil then
error("SecretKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`SecretKey must be a buffer, got {typeof(al)}`,2)
end

local an=buffer.len(al)
if an~=ag then
error(`SecretKey must be exactly {ag} bytes long, got {an} bytes`,2)
end

if am==nil then
error("PublicKey cannot be nil",2)
end

if typeof(am)~="buffer"then
error(`PublicKey must be a buffer, got {typeof(am)}`,2)
end

local ao=buffer.len(am)
if ao~=ah then
error(`PublicKey must be exactly {ah} bytes long, got {ao} bytes`,2)
end

if ak==nil then
error("Message cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Message must be a buffer, got {typeof(ak)}`,2)
end

local ap=ac(al)

local aq=buffer.create(32)
buffer.copy(aq,0,ap,0,32)
local ar=aa.DecodeClamped(aq)

local as=buffer.create(32)
buffer.copy(as,0,ap,32,32)

local at=ConcatBuffers(as,ak)
local au=ac(at)
local av=aa.DecodeWide(au)

local aw,ax=aa.Bits(av)
local ay=ad.MulG(aw,ax)
local az=ad.Encode(ay)

local aA=ConcatBuffers(az,am,ak)
local aB=ac(aA)
local aC=aa.DecodeWide(aB)

local aD=aa.Add(av,aa.Mul(ar,aC))
local aE=aa.Encode(aD)

return ConcatBuffers(az,aE)
end

function aj.Verify(ak:buffer,al:buffer,am:buffer):boolean
if al==nil then
error("PublicKey cannot be nil",2)
end

if typeof(al)~="buffer"then
error(`PublicKey must be a buffer, got {typeof(al)}`,2)
end

local an=buffer.len(al)
if an~=ah then
error(`PublicKey must be exactly {ah} bytes long, got {an} bytes`,2)
end

if ak==nil then
error("Message cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Message must be a buffer, got {typeof(ak)}`,2)
end

if am==nil then
error("Signature cannot be nil",2)
end

if typeof(am)~="buffer"then
error(`Signature must be a buffer, got {typeof(am)}`,2)
end

local ao=buffer.len(am)
if ao~=ai then
error(`Signature must be exactly {ai} bytes long, got {ao} bytes`,2)
end

local ap=buffer.readu8(am,63)
if bit32.band(ap,0xE0)~=0x00 then
return false
end

local aq=buffer.create(32)
buffer.copy(aq,0,am,0,32)
local ar=buffer.create(32)
buffer.copy(ar,0,am,32,32)

if not aa.IsValidScalar(ar)then
return false
end

local as=ad.Decode(al)
if not as then
return false
end

local at=ad.Decode(aq)
if not at then
return false
end

local au=ConcatBuffers(aq,al,ak)
local av=ac(au)
local aw=aa.DecodeWide(av)

local ax=aa.Decode(ar)
local ay,az=aa.Bits(ax)
local aA=ad.MulG(ay,az)

local aB,aC=aa.Bits(aw)
local aD=ad.Mul(as,aB,aC)

local aE=ad.Niels(aD)
local aF=ad.Add(at,aE)

local aG=ad.Niels(aA)
local aH=ad.Sub(aF,aG)

aH=ad.Double(aH)
aH=ad.Double(aH)
aH=ad.Double(aH)

local aI=buffer.create(104)
local aJ=buffer.create(104)
buffer.copy(aI,0,aH,0,104)
buffer.copy(aJ,0,aH,312,104)

local aK=ab.Eqz(aI)
local aL=ab.Eqz(aJ)

return aK and aL
end

function aj.VerifyBatch(ak:{SignatureEntry__DARKLUA_TYPE_g}):boolean
local al=#ak
if al==0 then
return true
end

if al==1 then
local am=ak[1]
return aj.Verify(am.Message,am.PublicKey,am.Signature)
end

local am={}
local an={}

for ao,ap in ak do
local aq=ap.PublicKey
local ar=ap.Message
local as=ap.Signature

if typeof(aq)~="buffer"or buffer.len(aq)~=ah then
return false
end

if typeof(ar)~="buffer"then
return false
end

if typeof(as)~="buffer"or buffer.len(as)~=ai then
return false
end

local at=buffer.readu8(as,63)
if bit32.band(at,0xE0)~=0x00 then
return false
end

local au=buffer.create(32)
buffer.copy(au,0,as,0,32)
local av=buffer.create(32)
buffer.copy(av,0,as,32,32)

if not aa.IsValidScalar(av)then
return false
end

local aw=ad.Decode(aq)
if not aw then
return false
end

local ax=ad.Decode(au)
if not ax then
return false
end

local ay=ConcatBuffers(au,aq,ar)
local az=ac(ay)
local aA=aa.DecodeWide(az)

local aB=aa.Decode(av)

table.insert(am,az)
table.insert(am,av)

an[ao]={
PublicPoint=aw,
CommitmentPoint=ax,
ChallengeScalar=aA,
ResponseScalar=aB,
}
end

local ao=ConcatBuffers(table.unpack(am))

local ap:buffer?
local aq:buffer?

for ar,as in an do
local at=buffer.create(2)
buffer.writeu16(at,0,ar)
local au=ConcatBuffers(at,ao)
local av=ac(au)

local aw=buffer.create(32)
buffer.copy(aw,0,av,0,32)
buffer.writeu8(aw,31,bit32.band(buffer.readu8(aw,31),0x0F))
local ax=aa.Decode(aw)

local ay=aa.Mul(ax,as.ResponseScalar)
if ap==nil then
ap=ay
else
ap=aa.Add(ap,ay)
end

local az=aa.Mul(ax,as.ChallengeScalar)
local aA,aB=aa.Bits(az)
local aC=ad.Mul(as.PublicPoint,aA,aB)

local aD,aE=aa.Bits(ax)
local aF=ad.Mul(as.CommitmentPoint,aD,aE)

local aG=ad.Niels(aC)
local aH=ad.Add(aF,aG)

if aq==nil then
aq=aH
else
local aI=ad.Niels(aH)
aq=ad.Add(aq,aI)
end
end

if ap==nil or aq==nil then
return false
end

local ar,as=aa.Bits(ap)
local at=ad.MulG(ar,as)

local au=ad.Niels(at)
local av=ad.Sub(aq::buffer,au)

av=ad.Double(av)
av=ad.Double(av)
av=ad.Double(av)

local aw=buffer.create(104)
local ax=buffer.create(104)
buffer.copy(aw,0,av,0,104)
buffer.copy(ax,0,av,312,104)

local ay=ab.Eqz(aw)
local az=ab.Eqz(ax)

return ay and az
end

return aj end function a.T():typeof(__modImpl())local aa=a.cache.T if not aa then aa={c=__modImpl()}a.cache.T=aa end return aa.c end end do local function __modImpl()




local aa={}

local ab,ac=buffer.create(96),buffer.create(96)do
local ad=0
local ae=29
local function GetNextBit():number
local af=ae%2
ae=bit32.bxor((ae-af)//2,142*af)

return af
end

for af=0,23 do
local ag=0
local ah:number

for ai=1,6 do
ah=if ah then ah*ah*2 else 1
ag+=GetNextBit()*ah
end

local ai=GetNextBit()*ah
buffer.writeu32(ac,af*4,ai)
buffer.writeu32(ab,af*4,ag+ai*ad)
end
end

local ad=buffer.create(100)
local ae=buffer.create(100)

local function Keccak(af:buffer,ag:buffer,ah:buffer,ai:number,aj:number,ak:number):()
local al=ak//8
local am,an=ac,ab

for ao=ai,ai+aj-1,ak do
for ap=0,(al-1)*4,4 do
local aq=ao+ap*2

buffer.writeu32(af,ap,bit32.bxor(
buffer.readu32(af,ap),
buffer.readu32(ah,aq)
))

buffer.writeu32(ag,ap,bit32.bxor(
buffer.readu32(ag,ap),
buffer.readu32(ah,aq+4)
))
end

local ap,aq=buffer.readu32(af,0),buffer.readu32(ag,0)
local ar,as=buffer.readu32(af,4),buffer.readu32(ag,4)
local at,au=buffer.readu32(af,8),buffer.readu32(ag,8)

local av,aw=buffer.readu32(af,12),buffer.readu32(ag,12)
local ax,ay=buffer.readu32(af,16),buffer.readu32(ag,16)
local az,aA=buffer.readu32(af,20),buffer.readu32(ag,20)

local aB,aC=buffer.readu32(af,24),buffer.readu32(ag,24)
local aD,aE=buffer.readu32(af,28),buffer.readu32(ag,28)
local aF,aG=buffer.readu32(af,32),buffer.readu32(ag,32)

local aH,aI=buffer.readu32(af,36),buffer.readu32(ag,36)
local aJ,aK=buffer.readu32(af,40),buffer.readu32(ag,40)
local aL,aM=buffer.readu32(af,44),buffer.readu32(ag,44)

local aN,aO=buffer.readu32(af,48),buffer.readu32(ag,48)
local aP,aQ=buffer.readu32(af,52),buffer.readu32(ag,52)
local aR,aS=buffer.readu32(af,56),buffer.readu32(ag,56)

local aT,aU=buffer.readu32(af,60),buffer.readu32(ag,60)
local aV,b=buffer.readu32(af,64),buffer.readu32(ag,64)
local c,d=buffer.readu32(af,68),buffer.readu32(ag,68)

local e,f=buffer.readu32(af,72),buffer.readu32(ag,72)
local g,h=buffer.readu32(af,76),buffer.readu32(ag,76)
local i,j=buffer.readu32(af,80),buffer.readu32(ag,80)

local k,l=buffer.readu32(af,84),buffer.readu32(ag,84)
local m,n=buffer.readu32(af,88),buffer.readu32(ag,88)
local o,p=buffer.readu32(af,92),buffer.readu32(ag,92)

local q,r=buffer.readu32(af,96),buffer.readu32(ag,96)

for s=0,92,4 do
local t,u=bit32.bxor(ap,az,aJ,aT,i),bit32.bxor(aq,aA,aK,aU,j)
local v,w=bit32.bxor(ar,aB,aL,aV,k),bit32.bxor(as,aC,aM,b,l)
local x,y=bit32.bxor(at,aD,aN,c,m),bit32.bxor(au,aE,aO,d,n)
local z,A=bit32.bxor(av,aF,aP,e,o),bit32.bxor(aw,aG,aQ,f,p)
local B,C=bit32.bxor(ax,aH,aR,g,q),bit32.bxor(ay,aI,aS,h,r)

local D,E=bit32.bxor(t,x*2+y//2147483648),bit32.bxor(u,y*2+x//2147483648)
local F,G=bit32.bxor(D,ar),bit32.bxor(E,as)
local H,I=bit32.bxor(D,aB),bit32.bxor(E,aC)
local J,K=bit32.bxor(D,aL),bit32.bxor(E,aM)
local L,M=bit32.bxor(D,aV),bit32.bxor(E,b)
local N,O=bit32.bxor(D,k),bit32.bxor(E,l)

ar=H//1048576+(I*4096);as=I//1048576+(H*4096)
aB=L//524288+(M*8192);aC=M//524288+(L*8192)
aL=F*2+G//2147483648;aM=G*2+F//2147483648
aV=J*1024+K//4194304;b=K*1024+J//4194304
k=N*4+O//1073741824;l=O*4+N//1073741824

D=bit32.bxor(v,z*2+A//2147483648);E=bit32.bxor(w,A*2+z//2147483648)
F=bit32.bxor(D,at);G=bit32.bxor(E,au)
H=bit32.bxor(D,aD);I=bit32.bxor(E,aE)
J=bit32.bxor(D,aN);K=bit32.bxor(E,aO)
L=bit32.bxor(D,c);M=bit32.bxor(E,d)
N=bit32.bxor(D,m);O=bit32.bxor(E,n)

at=J//2097152+(K*2048);au=K//2097152+(J*2048)
aD=N//8+bit32.bor(O*536870912,0);aE=O//8+bit32.bor(N*536870912,0)
aN=H*64+I//67108864;aO=I*64+H//67108864
c=(L*32768)+M//131072;d=(M*32768)+L//131072
m=F//4+bit32.bor(G*1073741824,0);n=G//4+bit32.bor(F*1073741824,0)

D=bit32.bxor(x,B*2+C//2147483648);E=bit32.bxor(y,C*2+B//2147483648)
F=bit32.bxor(D,av);G=bit32.bxor(E,aw)
H=bit32.bxor(D,aF);I=bit32.bxor(E,aG)
J=bit32.bxor(D,aP);K=bit32.bxor(E,aQ)
L=bit32.bxor(D,e);M=bit32.bxor(E,f)
N=bit32.bxor(D,o);O=bit32.bxor(E,p)

av=bit32.bor(L*2097152,0)+M//2048;aw=bit32.bor(M*2097152,0)+L//2048
aF=bit32.bor(F*268435456,0)+G//16;aG=bit32.bor(G*268435456,0)+F//16
aP=bit32.bor(J*33554432,0)+K//128;aQ=bit32.bor(K*33554432,0)+J//128
e=N//256+bit32.bor(O*16777216,0);f=O//256+bit32.bor(N*16777216,0)
o=H//512+bit32.bor(I*8388608,0);p=I//512+bit32.bor(H*8388608,0)
D=bit32.bxor(z,t*2+u//2147483648);E=bit32.bxor(A,u*2+t//2147483648)

F=bit32.bxor(D,ax);G=bit32.bxor(E,ay)
H=bit32.bxor(D,aH);I=bit32.bxor(E,aI)
J=bit32.bxor(D,aR);K=bit32.bxor(E,aS)
L=bit32.bxor(D,g);M=bit32.bxor(E,h)
N=bit32.bxor(D,q);O=bit32.bxor(E,r)

ax=(N*16384)+O//262144;ay=(O*16384)+N//262144
aH=bit32.bor(H*1048576,0)+I//4096;aI=bit32.bor(I*1048576,0)+H//4096
aR=L*256+M//16777216;aS=M*256+L//16777216
g=bit32.bor(F*134217728,0)+G//32;h=bit32.bor(G*134217728,0)+F//32
q=J//33554432+K*128;r=K//33554432+J*128

D=bit32.bxor(B,v*2+w//2147483648);E=bit32.bxor(C,w*2+v//2147483648)
H=bit32.bxor(D,az);I=bit32.bxor(E,aA)
J=bit32.bxor(D,aJ);K=bit32.bxor(E,aK)
L=bit32.bxor(D,aT);M=bit32.bxor(E,aU)
N=bit32.bxor(D,i);O=bit32.bxor(E,j)
az=J*8+K//536870912;aA=K*8+J//536870912
aJ=(N*262144)+O//16384;aK=(O*262144)+N//16384
aT=H//268435456+I*16;aU=I//268435456+H*16
i=L//8388608+M*512;j=M//8388608+L*512
ap=bit32.bxor(D,ap);aq=bit32.bxor(E,aq)

ap,ar,at,av,ax=bit32.bxor(ap,bit32.band(-1-ar,at)),bit32.bxor(ar,bit32.band(-1-at,av)),bit32.bxor(at,bit32.band(-1-av,ax)),bit32.bxor(av,bit32.band(-1-ax,ap)),bit32.bxor(ax,bit32.band(-1-ap,ar))::number
aq,as,au,aw,ay=bit32.bxor(aq,bit32.band(-1-as,au)),bit32.bxor(as,bit32.band(-1-au,aw)),bit32.bxor(au,bit32.band(-1-aw,ay)),bit32.bxor(aw,bit32.band(-1-ay,aq)),bit32.bxor(ay,bit32.band(-1-aq,as))::number
az,aB,aD,aF,aH=bit32.bxor(aF,bit32.band(-1-aH,az)),bit32.bxor(aH,bit32.band(-1-az,aB)),bit32.bxor(az,bit32.band(-1-aB,aD)),bit32.bxor(aB,bit32.band(-1-aD,aF)),bit32.bxor(aD,bit32.band(-1-aF,aH))::number
aA,aC,aE,aG,aI=bit32.bxor(aG,bit32.band(-1-aI,aA)),bit32.bxor(aI,bit32.band(-1-aA,aC)),bit32.bxor(aA,bit32.band(-1-aC,aE)),bit32.bxor(aC,bit32.band(-1-aE,aG)),bit32.bxor(aE,bit32.band(-1-aG,aI))::number
aJ,aL,aN,aP,aR=bit32.bxor(aL,bit32.band(-1-aN,aP)),bit32.bxor(aN,bit32.band(-1-aP,aR)),bit32.bxor(aP,bit32.band(-1-aR,aJ)),bit32.bxor(aR,bit32.band(-1-aJ,aL)),bit32.bxor(aJ,bit32.band(-1-aL,aN))::number
aK,aM,aO,aQ,aS=bit32.bxor(aM,bit32.band(-1-aO,aQ)),bit32.bxor(aO,bit32.band(-1-aQ,aS)),bit32.bxor(aQ,bit32.band(-1-aS,aK)),bit32.bxor(aS,bit32.band(-1-aK,aM)),bit32.bxor(aK,bit32.band(-1-aM,aO))::number
aT,aV,c,e,g=bit32.bxor(g,bit32.band(-1-aT,aV)),bit32.bxor(aT,bit32.band(-1-aV,c)),bit32.bxor(aV,bit32.band(-1-c,e)),bit32.bxor(c,bit32.band(-1-e,g)),bit32.bxor(e,bit32.band(-1-g,aT))::number
aU,b,d,f,h=bit32.bxor(h,bit32.band(-1-aU,b)),bit32.bxor(aU,bit32.band(-1-b,d)),bit32.bxor(b,bit32.band(-1-d,f)),bit32.bxor(d,bit32.band(-1-f,h)),bit32.bxor(f,bit32.band(-1-h,aU))::number
i,k,m,o,q=bit32.bxor(m,bit32.band(-1-o,q)),bit32.bxor(o,bit32.band(-1-q,i)),bit32.bxor(q,bit32.band(-1-i,k)),bit32.bxor(i,bit32.band(-1-k,m)),bit32.bxor(k,bit32.band(-1-m,o))::number
j,l,n,p,r=bit32.bxor(n,bit32.band(-1-p,r)),bit32.bxor(p,bit32.band(-1-r,j)),bit32.bxor(r,bit32.band(-1-j,l)),bit32.bxor(j,bit32.band(-1-l,n)),bit32.bxor(l,bit32.band(-1-n,p))::number

ap=bit32.bxor(ap,buffer.readu32(an,s))
aq=bit32.bxor(aq,buffer.readu32(am,s))
end

buffer.writeu32(af,0,ap);buffer.writeu32(ag,0,aq)
buffer.writeu32(af,4,ar);buffer.writeu32(ag,4,as)
buffer.writeu32(af,8,at);buffer.writeu32(ag,8,au)
buffer.writeu32(af,12,av);buffer.writeu32(ag,12,aw)
buffer.writeu32(af,16,ax);buffer.writeu32(ag,16,ay)
buffer.writeu32(af,20,az);buffer.writeu32(ag,20,aA)
buffer.writeu32(af,24,aB);buffer.writeu32(ag,24,aC)
buffer.writeu32(af,28,aD);buffer.writeu32(ag,28,aE)
buffer.writeu32(af,32,aF);buffer.writeu32(ag,32,aG)
buffer.writeu32(af,36,aH);buffer.writeu32(ag,36,aI)
buffer.writeu32(af,40,aJ);buffer.writeu32(ag,40,aK)
buffer.writeu32(af,44,aL);buffer.writeu32(ag,44,aM)
buffer.writeu32(af,48,aN);buffer.writeu32(ag,48,aO)
buffer.writeu32(af,52,aP);buffer.writeu32(ag,52,aQ)
buffer.writeu32(af,56,aR);buffer.writeu32(ag,56,aS)
buffer.writeu32(af,60,aT);buffer.writeu32(ag,60,aU)
buffer.writeu32(af,64,aV);buffer.writeu32(ag,64,b)
buffer.writeu32(af,68,c);buffer.writeu32(ag,68,d)
buffer.writeu32(af,72,e);buffer.writeu32(ag,72,f)
buffer.writeu32(af,76,g);buffer.writeu32(ag,76,h)
buffer.writeu32(af,80,i);buffer.writeu32(ag,80,j)
buffer.writeu32(af,84,k);buffer.writeu32(ag,84,l)
buffer.writeu32(af,88,m);buffer.writeu32(ag,88,n)
buffer.writeu32(af,92,o);buffer.writeu32(ag,92,p)
buffer.writeu32(af,96,q);buffer.writeu32(ag,96,r)
end
end

local function ProcessSponge(af:buffer,ag:number,ah:number,ai:number):buffer
local aj=(1600-ag)//8
buffer.fill(ad,0,0,100)
buffer.fill(ae,0,0,100)

local ak=ad
local al=ae

local am:number=buffer.len(af)
local an:number=am+1

local ao=an%aj
if ao~=0 then
an+=(aj-ao)
end

local ap=buffer.create(an)

if am>0 then
buffer.copy(ap,0,af,0,am)
end

if an-am==1 then
buffer.writeu8(ap,am,bit32.bor(ai,0x80))
else
buffer.writeu8(ap,am,ai)
if an-am>2 then
buffer.fill(ap,am+1,0,an-am-2)
end
buffer.writeu8(ap,an-1,0x80)
end

Keccak(ak,al,ap,0,an,aj)

local aq=buffer.create(ah)
local ar=0

local as=buffer.create(aj)
while ar<ah do
local at=math.min(aj,ah-ar)

for au=0,at-1 do
local av=ar+au
if av<ah then
local aw=au//8
local ax=au%8
local ay=aw*4

local az
if ax<4 then
az=bit32.extract(buffer.readu32(ak,ay),ax*8,8)
else
az=bit32.extract(buffer.readu32(al,ay),(ax-4)*8,8)
end
buffer.writeu8(aq,av,az)
end
end

ar+=at

if ar<ah then
Keccak(ak,al,as,0,aj,aj)
end
end

return aq
end

function aa.SHAKE128(af:buffer,ag:number):buffer
return ProcessSponge(af,256,ag,0x1F)
end

function aa.SHAKE256(af:buffer,ag:number):buffer
return ProcessSponge(af,512,ag,0x1F)
end

return aa end function a.U():typeof(__modImpl())local aa=a.cache.U if not aa then aa={c=__modImpl()}a.cache.U=aa end return aa.c end end do local function __modImpl()




















local aa=8380417

local ab={}

function ab.Add(ac:number,ad:number):number
local ae=ac+ad
return if ae>=aa then ae-aa else ae
end

function ab.Negate(ac:number):number
return if ac==0 then 0 else aa-ac
end

function ab.Subtract(ac:number,ad:number):number
local ae=ac-ad
return if ae<0 then ae+aa else ae
end

function ab.Multiply(ac:number,ad:number):number
return(ac*ad)%aa
end

function ab.Power(ac:number,ad:number):number
if ad==0 then
return 1
end

if ad==1 then
return ac%aa
end

local ae=1
local af=ac%aa
local ag=ad

while ag>0 do
if bit32.band(ag,1)==1 then
ae=ab.Multiply(ae,af)
end

af=ab.Multiply(af,af)
ag=bit32.rshift(ag,1)
end

return ae
end

function ab.Inverse(ac:number):number
return ab.Power(ac,aa-2)
end

function ab.Divide(ac:number,ad:number):number
return ab.Multiply(ac,ab.Inverse(ad))
end

return ab end function a.V():typeof(__modImpl())local aa=a.cache.V if not aa then aa={c=__modImpl()}a.cache.V=aa end return aa.c end end do local function __modImpl()



















local aa=a.V()

local ab=8
local ac=1753
local ad=8380417

local ae=bit32.lshift(1,ab)
local af=aa.Inverse(ae)

local ag,ah=buffer.create(ae*4),buffer.create(ae*4)do
for ai=0,ae-1 do
local aj=0
local ak=ai

for al=0,ab-1 do
local am=bit32.band(bit32.rshift(ak,al),1)
aj=bit32.bxor(aj,bit32.lshift(am,ab-1-al))
end

local al=aa.Power(ac,aj)
local am=aa.Negate(al)

buffer.writeu32(ag,ai*4,al)
buffer.writeu32(ah,ai*4,am)
end
end

local ai={}

function ai.ForwardNTT(aj:buffer)
local ak=ag
local al=ad

for am=ab-1,0,-1 do
local an=bit32.lshift(1,am)
local ao=bit32.lshift(an,1)
local ap=bit32.rshift(ae,am+1)

for aq=0,ae-1,ao do
local ar=ap+bit32.rshift(aq,am+1)
local as=buffer.readu32(ak,ar*4)

for at=aq,aq+an-1 do
local au=at*4
local av=(at+an)*4

local aw=buffer.readu32(aj,au)
local ax=buffer.readu32(aj,av)

local ay=(as*ax)%al

local az=if aw>=ay then aw-ay else aw-ay+al
local aA=aw+ay
aA=if aA>=al then aA-al else aA

buffer.writeu32(aj,av,az)
buffer.writeu32(aj,au,aA)
end
end
end
end

function ai.ForwardNTTWithOffset(aj:buffer,ak:number)
local al=ag
local am=ad

for an=ab-1,0,-1 do
local ao=bit32.lshift(1,an)
local ap=bit32.lshift(ao,1)
local aq=bit32.rshift(ae,an+1)

for ar=0,ae-1,ap do
local as=aq+bit32.rshift(ar,an+1)
local at=buffer.readu32(al,as*4)

for au=ar,ar+ao-1 do
local av=ak+au*4
local aw=ak+(au+ao)*4

local ax=buffer.readu32(aj,av)
local ay=buffer.readu32(aj,aw)

local az=(at*ay)%am

local aA=if ax>=az then ax-az else ax-az+am
local aB=ax+az
aB=if aB>=am then aB-am else aB

buffer.writeu32(aj,aw,aA)
buffer.writeu32(aj,av,aB)
end
end
end
end

function ai.InverseNTT(aj:buffer)
local ak=ah
local al=af
local am=ad

for an=0,ab-1 do
local ao=bit32.lshift(1,an)
local ap=bit32.lshift(ao,1)
local aq=bit32.rshift(ae,an)-1

for ar=0,ae-1,ap do
local as=aq-bit32.rshift(ar,an+1)
local at=buffer.readu32(ak,as*4)

for au=ar,ar+ao-1 do
local av=au*4
local aw=(au+ao)*4

local ax=buffer.readu32(aj,av)
local ay=buffer.readu32(aj,aw)

local az=ax+ay
az=if az>=am then az-am else az

local aA=if ax>=ay then ax-ay else ax-ay+am

local aB=(aA*at)%am

buffer.writeu32(aj,av,az)
buffer.writeu32(aj,aw,aB)
end
end
end

for an=0,ae-1 do
local ao=an*4
local ap=buffer.readu32(aj,ao)
local aq=(ap*al)%am
buffer.writeu32(aj,ao,aq)
end
end

ai.ZETA_NEG_EXP=ah
ai.INV_N=af

return ai end function a.W():typeof(__modImpl())local aa=a.cache.W if not aa then aa={c=__modImpl()}a.cache.W=aa end return aa.c end end do local function __modImpl()



















local aa=256
local ab=aa*4

local ac={}

function ac.Encode(ad:buffer,ae:buffer,af:number)
local ag=buffer.len(ae)
buffer.fill(ae,0,0,ag)

if af==3 then
for ah=0,31 do
local ai=ah*32
local aj=ah*3

local ak=bit32.band(buffer.readu32(ad,ai),0x7)
local al=bit32.band(buffer.readu32(ad,ai+4),0x7)
local am=bit32.band(buffer.readu32(ad,ai+8),0x7)
local an=bit32.band(buffer.readu32(ad,ai+12),0x7)
local ao=bit32.band(buffer.readu32(ad,ai+16),0x7)
local ap=bit32.band(buffer.readu32(ad,ai+20),0x7)
local aq=bit32.band(buffer.readu32(ad,ai+24),0x7)
local ar=bit32.band(buffer.readu32(ad,ai+28),0x7)

local as=bit32.bor(ak,bit32.lshift(al,3),bit32.lshift(am,6))
local at=bit32.bor(bit32.rshift(am,2),bit32.lshift(an,1),bit32.lshift(ao,4),bit32.lshift(ap,7))
local au=bit32.bor(bit32.rshift(ap,1),bit32.lshift(aq,2),bit32.lshift(ar,5))

buffer.writeu8(ae,aj,as)
buffer.writeu8(ae,aj+1,at)
buffer.writeu8(ae,aj+2,au)
end

elseif af==4 then
for ah=0,31 do
local ai=ah*32
local aj=ah*4

local ak=buffer.readu32(ad,ai)
local al=bit32.band(ak,0xF)
ak=buffer.readu32(ad,ai+4)
local am=bit32.band(ak,0xF)
ak=buffer.readu32(ad,ai+8)
local an=bit32.band(ak,0xF)
ak=buffer.readu32(ad,ai+12)
local ao=bit32.band(ak,0xF)
ak=buffer.readu32(ad,ai+16)
local ap=bit32.band(ak,0xF)
ak=buffer.readu32(ad,ai+20)
local aq=bit32.band(ak,0xF)
ak=buffer.readu32(ad,ai+24)
local ar=bit32.band(ak,0xF)
ak=buffer.readu32(ad,ai+28)
local as=bit32.band(ak,0xF)

buffer.writeu32(ae,aj,bit32.bor(
al,bit32.lshift(am,4),bit32.lshift(an,8),bit32.lshift(ao,12),
bit32.lshift(ap,16),bit32.lshift(aq,20),bit32.lshift(ar,24),bit32.lshift(as,28)
))
end

elseif af==6 then
for ah=0,63 do
local ai=ah*16
local aj=ah*3

local ak=bit32.band(buffer.readu32(ad,ai),0x3F)
local al=bit32.band(buffer.readu32(ad,ai+4),0x3F)
local am=bit32.band(buffer.readu32(ad,ai+8),0x3F)
local an=bit32.band(buffer.readu32(ad,ai+12),0x3F)

local ao=bit32.bor(ak,bit32.lshift(al,6),bit32.lshift(am,12),bit32.lshift(an,18))

buffer.writeu8(ae,aj,bit32.band(ao,0xFF))
buffer.writeu8(ae,aj+1,bit32.band(bit32.rshift(ao,8),0xFF))
buffer.writeu8(ae,aj+2,bit32.rshift(ao,16))
end

elseif af==10 then
for ah=0,63 do
local ai=ah*16
local aj=ah*5

local ak=bit32.band(buffer.readu32(ad,ai),0x3FF)
local al=bit32.band(buffer.readu32(ad,ai+4),0x3FF)
local am=bit32.band(buffer.readu32(ad,ai+8),0x3FF)
local an=bit32.band(buffer.readu32(ad,ai+12),0x3FF)

local ao=bit32.bor(ak,bit32.lshift(al,10),bit32.lshift(am,20))
local ap=bit32.bor(bit32.rshift(am,12),bit32.lshift(an,8))

buffer.writeu32(ae,aj,ao)
buffer.writeu8(ae,aj+4,bit32.band(ap,0xFF))
end

elseif af==13 then
for ah=0,31 do
local ai=ah*32
local aj=ah*13

local ak=bit32.band(buffer.readu32(ad,ai),0x1FFF)
local al=bit32.band(buffer.readu32(ad,ai+4),0x1FFF)
local am=bit32.band(buffer.readu32(ad,ai+8),0x1FFF)
local an=bit32.band(buffer.readu32(ad,ai+12),0x1FFF)
local ao=bit32.band(buffer.readu32(ad,ai+16),0x1FFF)
local ap=bit32.band(buffer.readu32(ad,ai+20),0x1FFF)
local aq=bit32.band(buffer.readu32(ad,ai+24),0x1FFF)
local ar=bit32.band(buffer.readu32(ad,ai+28),0x1FFF)

local as=bit32.bor(ak,bit32.lshift(al,13),bit32.lshift(am,26))
local at=bit32.bor(bit32.rshift(am,6),bit32.lshift(an,7),bit32.lshift(ao,20))
local au=bit32.bor(bit32.rshift(ao,12),bit32.lshift(ap,1),bit32.lshift(aq,14),bit32.lshift(ar,27))
local av=bit32.rshift(ar,5)

buffer.writeu32(ae,aj,as)
buffer.writeu32(ae,aj+4,at)
buffer.writeu32(ae,aj+8,au)
buffer.writeu8(ae,aj+12,av)
end

elseif af==18 then
for ah=0,63 do
local ai=ah*16
local aj=ah*9

local ak=bit32.band(buffer.readu32(ad,ai),0x3FFFF)
local al=bit32.band(buffer.readu32(ad,ai+4),0x3FFFF)
local am=bit32.band(buffer.readu32(ad,ai+8),0x3FFFF)
local an=bit32.band(buffer.readu32(ad,ai+12),0x3FFFF)

local ao=bit32.bor(ak,bit32.lshift(al,18))
local ap=bit32.bor(bit32.rshift(al,14),bit32.lshift(am,4),bit32.lshift(an,22))
local aq=bit32.rshift(an,10)

buffer.writeu32(ae,aj,ao)
buffer.writeu32(ae,aj+4,ap)
buffer.writeu8(ae,aj+8,aq)
end

elseif af==20 then
for ah=0,63 do
local ai=ah*16
local aj=ah*10

local ak=bit32.band(buffer.readu32(ad,ai),0xFFFFF)
local al=bit32.band(buffer.readu32(ad,ai+4),0xFFFFF)
local am=bit32.band(buffer.readu32(ad,ai+8),0xFFFFF)
local an=bit32.band(buffer.readu32(ad,ai+12),0xFFFFF)

local ao=bit32.bor(ak,bit32.lshift(al,20))
local ap=bit32.bor(bit32.rshift(al,12),bit32.lshift(am,8),bit32.lshift(an,28))
local aq=bit32.rshift(an,4)

buffer.writeu32(ae,aj,ao)
buffer.writeu32(ae,aj+4,ap)
buffer.writeu16(ae,aj+8,aq)
end

else
local ah=bit32.lshift(1,af)-1
local ai=0

for aj=0,aa-1 do
local ak=bit32.band(buffer.readu32(ad,aj*4),ah)
local al=af

while al>0 do
local am=bit32.rshift(ai,3)
local an=bit32.band(ai,7)
local ao=math.min(al,8-an)

local ap=bit32.lshift(1,ao)-1
local aq=bit32.band(ak,ap)
local ar=buffer.readu8(ae,am)

buffer.writeu8(ae,am,bit32.bor(ar,bit32.lshift(aq,an)))

ak=bit32.rshift(ak,ao)
ai+=ao
al-=ao
end
end
end
end

function ac.Decode(ad:buffer,ae:buffer,af:number)
buffer.fill(ae,0,0,ab)

if af==3 then
for ag=0,31 do
local ah=ag*3
local ai=ag*32

local aj=buffer.readu8(ad,ah)
local ak=buffer.readu8(ad,ah+1)
local al=buffer.readu8(ad,ah+2)

buffer.writeu32(ae,ai,bit32.band(aj,0x7))
buffer.writeu32(ae,ai+4,bit32.band(bit32.rshift(aj,3),0x7))
buffer.writeu32(ae,ai+8,bit32.bor(bit32.rshift(aj,6),bit32.lshift(bit32.band(ak,0x1),2)))
buffer.writeu32(ae,ai+12,bit32.band(bit32.rshift(ak,1),0x7))
buffer.writeu32(ae,ai+16,bit32.band(bit32.rshift(ak,4),0x7))
buffer.writeu32(ae,ai+20,bit32.bor(bit32.rshift(ak,7),bit32.lshift(bit32.band(al,0x3),1)))
buffer.writeu32(ae,ai+24,bit32.band(bit32.rshift(al,2),0x7))
buffer.writeu32(ae,ai+28,bit32.rshift(al,5))
end

elseif af==4 then
for ag=0,31 do
local ah=ag*4
local ai=ag*32

local aj=buffer.readu32(ad,ah)

buffer.writeu32(ae,ai,bit32.band(aj,0xF))
buffer.writeu32(ae,ai+4,bit32.band(bit32.rshift(aj,4),0xF))
buffer.writeu32(ae,ai+8,bit32.band(bit32.rshift(aj,8),0xF))
buffer.writeu32(ae,ai+12,bit32.band(bit32.rshift(aj,12),0xF))
buffer.writeu32(ae,ai+16,bit32.band(bit32.rshift(aj,16),0xF))
buffer.writeu32(ae,ai+20,bit32.band(bit32.rshift(aj,20),0xF))
buffer.writeu32(ae,ai+24,bit32.band(bit32.rshift(aj,24),0xF))
buffer.writeu32(ae,ai+28,bit32.rshift(aj,28))
end

elseif af==6 then
for ag=0,63 do
local ah=ag*3
local ai=ag*16

local aj=buffer.readu8(ad,ah)
local ak=buffer.readu8(ad,ah+1)
local al=buffer.readu8(ad,ah+2)

local am=bit32.bor(aj,bit32.lshift(ak,8),bit32.lshift(al,16))

buffer.writeu32(ae,ai,bit32.band(am,0x3F))
buffer.writeu32(ae,ai+4,bit32.band(bit32.rshift(am,6),0x3F))
buffer.writeu32(ae,ai+8,bit32.band(bit32.rshift(am,12),0x3F))
buffer.writeu32(ae,ai+12,bit32.rshift(am,18))
end

elseif af==10 then
for ag=0,63 do
local ah=ag*5
local ai=ag*16

local aj=buffer.readu32(ad,ah)
local ak=buffer.readu8(ad,ah+4)

buffer.writeu32(ae,ai,bit32.band(aj,0x3FF))
buffer.writeu32(ae,ai+4,bit32.band(bit32.rshift(aj,10),0x3FF))
buffer.writeu32(ae,ai+8,bit32.bor(bit32.rshift(aj,20),bit32.lshift(bit32.band(ak,0x3),12)))
buffer.writeu32(ae,ai+12,bit32.rshift(ak,2))
end

elseif af==13 then
for ag=0,31 do
local ah=ag*13
local ai=ag*32

local aj=buffer.readu32(ad,ah)
local ak=buffer.readu32(ad,ah+4)
local al=buffer.readu32(ad,ah+8)
local am=buffer.readu8(ad,ah+12)

buffer.writeu32(ae,ai,bit32.band(aj,0x1FFF))
buffer.writeu32(ae,ai+4,bit32.band(bit32.rshift(aj,13),0x1FFF))
buffer.writeu32(ae,ai+8,bit32.bor(bit32.rshift(aj,26),bit32.lshift(bit32.band(ak,0x7F),6)))
buffer.writeu32(ae,ai+12,bit32.band(bit32.rshift(ak,7),0x1FFF))
buffer.writeu32(ae,ai+16,bit32.bor(bit32.rshift(ak,20),bit32.lshift(bit32.band(al,0x1),12)))
buffer.writeu32(ae,ai+20,bit32.band(bit32.rshift(al,1),0x1FFF))
buffer.writeu32(ae,ai+24,bit32.band(bit32.rshift(al,14),0x1FFF))
buffer.writeu32(ae,ai+28,bit32.bor(bit32.rshift(al,27),bit32.lshift(am,5)))
end

elseif af==18 then
for ag=0,63 do
local ah=ag*9
local ai=ag*16

local aj=buffer.readu32(ad,ah)
local ak=buffer.readu32(ad,ah+4)
local al=buffer.readu8(ad,ah+8)

buffer.writeu32(ae,ai,bit32.band(aj,0x3FFFF))
buffer.writeu32(ae,ai+4,bit32.bor(bit32.rshift(aj,18),bit32.lshift(bit32.band(ak,0xF),14)))
buffer.writeu32(ae,ai+8,bit32.band(bit32.rshift(ak,4),0x3FFFF))
buffer.writeu32(ae,ai+12,bit32.bor(bit32.rshift(ak,22),bit32.lshift(al,10)))
end

elseif af==20 then
for ag=0,63 do
local ah=ag*10
local ai=ag*16

local aj=buffer.readu32(ad,ah)
local ak=buffer.readu32(ad,ah+4)
local al=buffer.readu16(ad,ah+8)

buffer.writeu32(ae,ai,bit32.band(aj,0xFFFFF))
buffer.writeu32(ae,ai+4,bit32.bor(bit32.rshift(aj,20),bit32.lshift(bit32.band(ak,0xFF),12)))
buffer.writeu32(ae,ai+8,bit32.bor(bit32.rshift(ak,8),bit32.lshift(bit32.band(al,0xF),24)))
buffer.writeu32(ae,ai+12,bit32.bor(bit32.rshift(ak,28),bit32.lshift(al,4)))
end

else
local ag=bit32.lshift(1,af)-1
local ah=0

for ai=0,aa-1 do
local aj=0
local ak=0

while ak<af do
local al=bit32.rshift(ah,3)
local am=bit32.band(ah,7)
local an=8-am
local ao=math.min(af-ak,an)

local ap=buffer.readu8(ad,al)
local aq=bit32.band(bit32.rshift(ap,am),bit32.lshift(1,ao)-1)

aj=bit32.bor(aj,bit32.lshift(aq,ak))

ah+=ao
ak+=ao
end

buffer.writeu32(ae,ai*4,bit32.band(aj,ag))
end
end
end

function ac.EncodeHintBits(ad:buffer,ae:buffer,af:number,ag:number)
buffer.fill(ae,0,0,ag+af)

local ah=0

for ai=0,af-1 do
local aj=ai*aa*4

for ak=0,aa-1 do
if buffer.readu32(ad,aj+ak*4)~=0 then
buffer.writeu8(ae,ah,ak)
ah+=1

if ah>=ag then
break
end
end
end

buffer.writeu8(ae,ag+ai,ah)
end
end

function ac.DecodeHintBits(ad:buffer,ae:buffer,af:number,ag:number):boolean
buffer.fill(ae,0,0,af*aa*4)

local ah=0
local ai=false

for aj=0,af-1 do
local ak=aj*aa*4
local al=buffer.readu8(ad,ag+aj)

if al<ah or al>ag then
ai=true
end

if not ai then
local am=-1

for an=ah,al-1 do
local ao=buffer.readu8(ad,an)

if ao<=am or ao>=aa then
ai=true
break
end

buffer.writeu32(ae,ak+ao*4,1)
am=ao
end
end

ah=al
end

if not ai then
for aj=ah,ag-1 do
if buffer.readu8(ad,aj)~=0 then
ai=true
break
end
end
end

return ai
end

return ac end function a.X():typeof(__modImpl())local aa=a.cache.X if not aa then aa={c=__modImpl()}a.cache.X=aa end return aa.c end end do local function __modImpl()


















local aa=a.V()
local ab=a.W()
local ac=a.X()

local ad=8
local ae=1753
local af=8380417

local ag=256
local ah=aa.Inverse(ag)

local ai,aj=buffer.create(ag*4),buffer.create(ag*4)do
for ak=0,ag-1 do
local al=0
local am=ak

for an=0,ad-1 do
local ao=bit32.band(bit32.rshift(am,an),1)
al=bit32.bxor(al,bit32.lshift(ao,ad-1-an))
end

local an=aa.Power(ae,al)
local ao=aa.Negate(an)

buffer.writeu32(ai,ak*4,an)
buffer.writeu32(aj,ak*4,ao)
end
end

local ak={}

function ak.ForwardNTT(al:buffer,am:number)
local an=ag
for ao=0,am-1 do
local ap=ao*an*4
ab.ForwardNTTWithOffset(al,ap)
end
end

function ak.InverseNTT(al:buffer,am:number)
local an=aj
local ao=ah
local ap=ag
local aq=af

for ar=0,am-1 do
local as=ar*ap*4

for at=0,7 do
local au=bit32.lshift(1,at)
local av=bit32.lshift(au,1)
local aw=bit32.rshift(ap,at)-1

for ax=0,ap-1,av do
local ay=aw-bit32.rshift(ax,at+1)
local az=buffer.readu32(an,ay*4)

for aA=ax,ax+au-1 do
local aB=as+aA*4
local aC=as+(aA+au)*4

local aD=buffer.readu32(al,aB)
local aE=buffer.readu32(al,aC)

local aF=aD+aE
aF=if aF>=aq then aF-aq else aF

local aG=if aD>=aE then aD-aE else aD-aE+aq
local aH=(aG*az)%aq

buffer.writeu32(al,aB,aF)
buffer.writeu32(al,aC,aH)
end
end
end

for at=0,ap-1 do
local au=as+at*4
local av=buffer.readu32(al,au)
local aw=(av*ao)%aq
buffer.writeu32(al,au,aw)
end
end
end

function ak.Power2Round(al:buffer,am:buffer,an:buffer,ao:number,ap:number)
local aq=bit32.lshift(1,ap-1)
local ar=ag
local as=af

for at=0,ao-1 do
local au=at*ar*4

for av=0,ar-1 do
local aw=au+av*4
local ax=buffer.readu32(al,aw)

local ay=ax+aq-1
local az=bit32.rshift(ay,ap)
local aA=bit32.lshift(az,ap)

local aB=az
local aC=if ax>=aA then ax-aA else ax-aA+as

buffer.writeu32(am,aw,aB)
buffer.writeu32(an,aw,aC)
end
end
end

function ak.MatrixMultiply(al:buffer,am:buffer,an:buffer,ao:number,ap:number,aq:number,ar:number)
local as=ag
local at=af

buffer.fill(an,0,0,ao*ar*ag*4)

for au=0,ao-1 do
for av=0,ar-1 do
local aw=(au*ar+av)*as*4

for ax=0,ap-1 do
local ay=(au*ap+ax)*as*4
local az=(ax*ar+av)*as*4

for aA=0,as-1 do
local aB=aA*4
local aC=buffer.readu32(al,ay+aB)
local aD=buffer.readu32(am,az+aB)

local aE=(aC*aD)%at

local aF=buffer.readu32(an,aw+aB)
local aG=aF+aE
aG=if aG>=at then aG-at else aG

buffer.writeu32(an,aw+aB,aG)
end
end
end
end
end

function ak.AddTo(al:buffer,am:buffer,an:number)
local ao=an*ag
local ap=af

for aq=0,ao-1 do
local ar=aq*4
local as=buffer.readu32(al,ar)
local at=buffer.readu32(am,ar)

local au=at+as
au=if au>=ap then au-ap else au

buffer.writeu32(am,ar,au)
end
end

function ak.Negate(al:buffer,am:number)
local an=am*ag
local ao=af

for ap=0,an-1 do
local aq=ap*4
local ar=buffer.readu32(al,aq)
local as=if ar==0 then 0 else ao-ar

buffer.writeu32(al,aq,as)
end
end

function ak.SubFromX(al:buffer,am:number,an:number)
local ao=af
local ap=ag
for aq=0,am-1 do
local ar=aq*ap*4

for as=0,ap-1 do
local at=ar+as*4
local au=buffer.readu32(al,at)

local av=if an>=au then an-au else an-au+ao

buffer.writeu32(al,at,av)
end
end
end

function ak.Encode(al:buffer,am:buffer,an:number,ao:number)
local ap=math.floor((ag*ao)/8)
local aq=ag

for ar=0,an-1 do
local as=ar*aq*4
local at=ar*ap

if ao==3 then
local au=32
for av=0,au-1 do
local aw=as+av*32
local ax=at+av*3

local ay=bit32.band(buffer.readu32(al,aw+0),0x7)
local az=bit32.band(buffer.readu32(al,aw+4),0x7)
local aA=bit32.band(buffer.readu32(al,aw+8),0x7)
local aB=bit32.band(buffer.readu32(al,aw+12),0x7)
local aC=bit32.band(buffer.readu32(al,aw+16),0x7)
local aD=bit32.band(buffer.readu32(al,aw+20),0x7)
local aE=bit32.band(buffer.readu32(al,aw+24),0x7)
local aF=bit32.band(buffer.readu32(al,aw+28),0x7)

buffer.writeu8(am,ax+0,bit32.bor(bit32.lshift(bit32.band(aA,0x3),6),bit32.lshift(az,3),ay))
buffer.writeu8(am,ax+1,bit32.bor(bit32.lshift(bit32.band(aD,0x1),7),bit32.lshift(aC,4),bit32.lshift(aB,1),bit32.rshift(aA,2)))
buffer.writeu8(am,ax+2,bit32.bor(bit32.lshift(aF,5),bit32.lshift(aE,2),bit32.rshift(aD,1)))
end
elseif ao==4 then
for au=0,127 do
local av=as+au*8
local aw=bit32.band(buffer.readu32(al,av),0xF)
local ax=bit32.band(buffer.readu32(al,av+4),0xF)
buffer.writeu8(am,at+au,bit32.bor(bit32.lshift(ax,4),aw))
end
elseif ao==6 then
for au=0,63 do
local av=as+au*16
local aw=at+au*3

local ax=bit32.band(buffer.readu32(al,av+0),0x3F)
local ay=bit32.band(buffer.readu32(al,av+4),0x3F)
local az=bit32.band(buffer.readu32(al,av+8),0x3F)
local aA=bit32.band(buffer.readu32(al,av+12),0x3F)

buffer.writeu8(am,aw+0,bit32.bor(bit32.lshift(bit32.band(ay,0x3),6),ax))
buffer.writeu8(am,aw+1,bit32.bor(bit32.lshift(bit32.band(az,0xF),4),bit32.rshift(ay,2)))
buffer.writeu8(am,aw+2,bit32.bor(bit32.lshift(aA,2),bit32.rshift(az,4)))
end
elseif ao==10 then
for au=0,63 do
local av=as+au*16
local aw=at+au*5

local ax=bit32.band(buffer.readu32(al,av+0),0x3FF)
local ay=bit32.band(buffer.readu32(al,av+4),0x3FF)
local az=bit32.band(buffer.readu32(al,av+8),0x3FF)
local aA=bit32.band(buffer.readu32(al,av+12),0x3FF)

buffer.writeu8(am,aw+0,bit32.band(ax,0xFF))
buffer.writeu8(am,aw+1,bit32.bor(bit32.lshift(bit32.band(ay,0x3F),2),bit32.rshift(ax,8)))
buffer.writeu8(am,aw+2,bit32.bor(bit32.lshift(bit32.band(az,0xF),4),bit32.rshift(ay,6)))
buffer.writeu8(am,aw+3,bit32.bor(bit32.lshift(bit32.band(aA,0x3),6),bit32.rshift(az,4)))
buffer.writeu8(am,aw+4,bit32.rshift(aA,2))
end
elseif ao==13 then
for au=0,31 do
local av=as+au*32
local aw=at+au*13

local ax=bit32.band(buffer.readu32(al,av+0),0x1FFF)
local ay=bit32.band(buffer.readu32(al,av+4),0x1FFF)
local az=bit32.band(buffer.readu32(al,av+8),0x1FFF)
local aA=bit32.band(buffer.readu32(al,av+12),0x1FFF)
local aB=bit32.band(buffer.readu32(al,av+16),0x1FFF)
local aC=bit32.band(buffer.readu32(al,av+20),0x1FFF)
local aD=bit32.band(buffer.readu32(al,av+24),0x1FFF)
local aE=bit32.band(buffer.readu32(al,av+28),0x1FFF)

buffer.writeu8(am,aw+0,bit32.band(ax,0xFF))
buffer.writeu8(am,aw+1,bit32.bor(bit32.lshift(bit32.band(ay,0x7),5),bit32.rshift(ax,8)))
buffer.writeu8(am,aw+2,bit32.rshift(ay,3))
buffer.writeu8(am,aw+3,bit32.bor(bit32.lshift(bit32.band(az,0x3F),2),bit32.rshift(ay,11)))
buffer.writeu8(am,aw+4,bit32.bor(bit32.lshift(bit32.band(aA,0x1),7),bit32.rshift(az,6)))
buffer.writeu8(am,aw+5,bit32.rshift(aA,1))
buffer.writeu8(am,aw+6,bit32.bor(bit32.lshift(bit32.band(aB,0xF),4),bit32.rshift(aA,9)))
buffer.writeu8(am,aw+7,bit32.rshift(aB,4))
buffer.writeu8(am,aw+8,bit32.bor(bit32.lshift(bit32.band(aC,0x7F),1),bit32.rshift(aB,12)))
buffer.writeu8(am,aw+9,bit32.bor(bit32.lshift(bit32.band(aD,0x3),6),bit32.rshift(aC,7)))
buffer.writeu8(am,aw+10,bit32.rshift(aD,2))
buffer.writeu8(am,aw+11,bit32.bor(bit32.lshift(bit32.band(aE,0x1F),3),bit32.rshift(aD,10)))
buffer.writeu8(am,aw+12,bit32.rshift(aE,5))
end
elseif ao==18 then
for au=0,63 do
local av=as+au*16
local aw=at+au*9

local ax=bit32.band(buffer.readu32(al,av+0),0x3FFFF)
local ay=bit32.band(buffer.readu32(al,av+4),0x3FFFF)
local az=bit32.band(buffer.readu32(al,av+8),0x3FFFF)
local aA=bit32.band(buffer.readu32(al,av+12),0x3FFFF)

buffer.writeu8(am,aw+0,bit32.band(ax,0xFF))
buffer.writeu8(am,aw+1,bit32.band(bit32.rshift(ax,8),0xFF))
buffer.writeu8(am,aw+2,bit32.bor(bit32.rshift(ax,16),bit32.lshift(bit32.band(ay,0x3F),2)))
buffer.writeu8(am,aw+3,bit32.band(bit32.rshift(ay,6),0xFF))
buffer.writeu8(am,aw+4,bit32.bor(bit32.rshift(ay,14),bit32.lshift(bit32.band(az,0xF),4)))
buffer.writeu8(am,aw+5,bit32.band(bit32.rshift(az,4),0xFF))
buffer.writeu8(am,aw+6,bit32.bor(bit32.rshift(az,12),bit32.lshift(bit32.band(aA,0x3),6)))
buffer.writeu8(am,aw+7,bit32.band(bit32.rshift(aA,2),0xFF))
buffer.writeu8(am,aw+8,bit32.rshift(aA,10))
end
elseif ao==20 then
for au=0,63 do
local av=as+au*16
local aw=at+au*10

local ax=bit32.band(buffer.readu32(al,av+0),0xFFFFF)
local ay=bit32.band(buffer.readu32(al,av+4),0xFFFFF)
local az=bit32.band(buffer.readu32(al,av+8),0xFFFFF)
local aA=bit32.band(buffer.readu32(al,av+12),0xFFFFF)

buffer.writeu8(am,aw+0,bit32.band(ax,0xFF))
buffer.writeu8(am,aw+1,bit32.band(bit32.rshift(ax,8),0xFF))
buffer.writeu8(am,aw+2,bit32.bor(bit32.rshift(ax,16),bit32.lshift(bit32.band(ay,0xF),4)))
buffer.writeu8(am,aw+3,bit32.band(bit32.rshift(ay,4),0xFF))
buffer.writeu8(am,aw+4,bit32.band(bit32.rshift(ay,12),0xFF))
buffer.writeu8(am,aw+5,bit32.band(az,0xFF))
buffer.writeu8(am,aw+6,bit32.band(bit32.rshift(az,8),0xFF))
buffer.writeu8(am,aw+7,bit32.bor(bit32.rshift(az,16),bit32.lshift(bit32.band(aA,0xF),4)))
buffer.writeu8(am,aw+8,bit32.band(bit32.rshift(aA,4),0xFF))
buffer.writeu8(am,aw+9,bit32.rshift(aA,12))
end
else
local au=buffer.create(ag*4)
local av=buffer.create(ap)
buffer.copy(au,0,al,as,ag*4)
ac.Encode(au,av,ao)
buffer.copy(am,at,av,0,ap)
end
end
end

function ak.Decode(al:buffer,am:buffer,an:number,ao:number)
local ap=math.floor((ag*ao)/8)
local aq=ag

for ar=0,an-1 do
local as=ar*ap
local at=ar*aq*4

if ao==3 then
for au=0,31 do
local av=as+au*3
local aw=at+au*32

local ax=buffer.readu8(al,av+0)
local ay=buffer.readu8(al,av+1)
local az=buffer.readu8(al,av+2)

buffer.writeu32(am,aw+0,bit32.band(ax,0x7))
buffer.writeu32(am,aw+4,bit32.band(bit32.rshift(ax,3),0x7))
buffer.writeu32(am,aw+8,bit32.bor(bit32.rshift(ax,6),bit32.lshift(bit32.band(ay,0x1),2)))
buffer.writeu32(am,aw+12,bit32.band(bit32.rshift(ay,1),0x7))
buffer.writeu32(am,aw+16,bit32.band(bit32.rshift(ay,4),0x7))
buffer.writeu32(am,aw+20,bit32.bor(bit32.rshift(ay,7),bit32.lshift(bit32.band(az,0x3),1)))
buffer.writeu32(am,aw+24,bit32.band(bit32.rshift(az,2),0x7))
buffer.writeu32(am,aw+28,bit32.rshift(az,5))
end
elseif ao==4 then
for au=0,127 do
local av=buffer.readu8(al,as+au)
local aw=at+au*8
buffer.writeu32(am,aw,bit32.band(av,0xF))
buffer.writeu32(am,aw+4,bit32.rshift(av,4))
end
elseif ao==6 then
for au=0,63 do
local av=as+au*3
local aw=at+au*16

local ax=buffer.readu8(al,av+0)
local ay=buffer.readu8(al,av+1)
local az=buffer.readu8(al,av+2)

buffer.writeu32(am,aw+0,bit32.band(ax,0x3F))
buffer.writeu32(am,aw+4,bit32.bor(bit32.rshift(ax,6),bit32.lshift(bit32.band(ay,0xF),2)))
buffer.writeu32(am,aw+8,bit32.bor(bit32.rshift(ay,4),bit32.lshift(bit32.band(az,0x3),4)))
buffer.writeu32(am,aw+12,bit32.rshift(az,2))
end
elseif ao==10 then
for au=0,63 do
local av=as+au*5
local aw=at+au*16

local ax=buffer.readu8(al,av+0)
local ay=buffer.readu8(al,av+1)
local az=buffer.readu8(al,av+2)
local aA=buffer.readu8(al,av+3)
local aB=buffer.readu8(al,av+4)

buffer.writeu32(am,aw+0,bit32.bor(ax,bit32.lshift(bit32.band(ay,0x3),8)))
buffer.writeu32(am,aw+4,bit32.bor(bit32.rshift(ay,2),bit32.lshift(bit32.band(az,0xF),6)))
buffer.writeu32(am,aw+8,bit32.bor(bit32.rshift(az,4),bit32.lshift(bit32.band(aA,0x3F),4)))
buffer.writeu32(am,aw+12,bit32.bor(bit32.rshift(aA,6),bit32.lshift(aB,2)))
end
elseif ao==13 then
for au=0,31 do
local av=as+au*13
local aw=at+au*32

local ax=buffer.readu8(al,av+0)
local ay=buffer.readu8(al,av+1)
local az=buffer.readu8(al,av+2)
local aA=buffer.readu8(al,av+3)
local aB=buffer.readu8(al,av+4)
local aC=buffer.readu8(al,av+5)
local aD=buffer.readu8(al,av+6)
local aE=buffer.readu8(al,av+7)
local aF=buffer.readu8(al,av+8)
local aG=buffer.readu8(al,av+9)
local aH=buffer.readu8(al,av+10)
local aI=buffer.readu8(al,av+11)
local aJ=buffer.readu8(al,av+12)

buffer.writeu32(am,aw+0,bit32.bor(ax,bit32.lshift(bit32.band(ay,0x1F),8)))
buffer.writeu32(am,aw+4,bit32.bor(bit32.rshift(ay,5),bit32.lshift(az,3),bit32.lshift(bit32.band(aA,0x3),11)))
buffer.writeu32(am,aw+8,bit32.bor(bit32.rshift(aA,2),bit32.lshift(bit32.band(aB,0x7F),6)))
buffer.writeu32(am,aw+12,bit32.bor(bit32.rshift(aB,7),bit32.lshift(aC,1),bit32.lshift(bit32.band(aD,0xF),9)))
buffer.writeu32(am,aw+16,bit32.bor(bit32.rshift(aD,4),bit32.lshift(aE,4),bit32.lshift(bit32.band(aF,0x1),12)))
buffer.writeu32(am,aw+20,bit32.bor(bit32.rshift(aF,1),bit32.lshift(bit32.band(aG,0x3F),7)))
buffer.writeu32(am,aw+24,bit32.bor(bit32.rshift(aG,6),bit32.lshift(aH,2),bit32.lshift(bit32.band(aI,0x7),10)))
buffer.writeu32(am,aw+28,bit32.bor(bit32.rshift(aI,3),bit32.lshift(aJ,5)))
end
elseif ao==18 then
for au=0,63 do
local av=as+au*9
local aw=at+au*16

local ax=buffer.readu8(al,av+0)
local ay=buffer.readu8(al,av+1)
local az=buffer.readu8(al,av+2)
local aA=buffer.readu8(al,av+3)
local aB=buffer.readu8(al,av+4)
local aC=buffer.readu8(al,av+5)
local aD=buffer.readu8(al,av+6)
local aE=buffer.readu8(al,av+7)
local aF=buffer.readu8(al,av+8)

buffer.writeu32(am,aw+0,bit32.bor(ax,bit32.lshift(ay,8),bit32.lshift(bit32.band(az,0x3),16)))
buffer.writeu32(am,aw+4,bit32.bor(bit32.rshift(az,2),bit32.lshift(aA,6),bit32.lshift(bit32.band(aB,0xF),14)))
buffer.writeu32(am,aw+8,bit32.bor(bit32.rshift(aB,4),bit32.lshift(aC,4),bit32.lshift(bit32.band(aD,0x3F),12)))
buffer.writeu32(am,aw+12,bit32.bor(bit32.rshift(aD,6),bit32.lshift(aE,2),bit32.lshift(aF,10)))
end
elseif ao==20 then
for au=0,63 do
local av=as+au*10
local aw=at+au*16

local ax=buffer.readu8(al,av+0)
local ay=buffer.readu8(al,av+1)
local az=buffer.readu8(al,av+2)
local aA=buffer.readu8(al,av+3)
local aB=buffer.readu8(al,av+4)
local aC=buffer.readu8(al,av+5)
local aD=buffer.readu8(al,av+6)
local aE=buffer.readu8(al,av+7)
local aF=buffer.readu8(al,av+8)
local aG=buffer.readu8(al,av+9)

buffer.writeu32(am,aw+0,bit32.bor(ax,bit32.lshift(ay,8),bit32.lshift(bit32.band(az,0xF),16)))
buffer.writeu32(am,aw+4,bit32.bor(bit32.rshift(az,4),bit32.lshift(aA,4),bit32.lshift(aB,12)))
buffer.writeu32(am,aw+8,bit32.bor(aC,bit32.lshift(aD,8),bit32.lshift(bit32.band(aE,0xF),16)))
buffer.writeu32(am,aw+12,bit32.bor(bit32.rshift(aE,4),bit32.lshift(aF,4),bit32.lshift(aG,12)))
end
else
local au=buffer.create(ap)
local av=buffer.create(ag*4)
buffer.copy(au,0,al,as,ap)
ac.Decode(au,av,ao)
buffer.copy(am,at,av,0,ag*4)
end
end
end

function ak.HighBits(al:buffer,am:buffer,an:number,ao:number)
local ap=bit32.rshift(ao,1)
local aq=af-1
local ar=af
local as=ag

for at=0,an-1 do
local au=at*as*4

for av=0,as-1 do
local aw=au+av*4
local ax=buffer.readu32(al,aw)

local ay=ax+ap-1
local az=math.floor(ay/ao)
local aA=az*ao

local aB=if ax>=aA then ax-aA else ax-aA+ar
local aC=if ax>=aB then ax-aB else ax-aB+ar

local aD=(aC==aq)
local aE=if aD then 0 else az

buffer.writeu32(am,aw,aE)
end
end
end

function ak.LowBits(al:buffer,am:buffer,an:number,ao:number)
local ap=bit32.rshift(ao,1)
local aq=af-1

local ar=af
local as=ag

for at=0,an-1 do
local au=at*as*4

for av=0,as-1 do
local aw=au+av*4
local ax=buffer.readu32(al,aw)

local ay=ax+ap-1
local az=math.floor(ay/ao)
local aA=az*ao

local aB=if ax>=aA then ax-aA else ax-aA+ar
local aC=if ax>=aB then ax-aB else ax-aB+ar

local aD=(aC==aq)
local aE=if aD then(if aB>=1 then aB-1 else aB-1+ar)else aB

buffer.writeu32(am,aw,aE)
end
end
end

function ak.MultiplyByPoly(al:buffer,am:buffer,an:buffer,ao:number)
local ap=af
local aq=ag

for ar=0,ao-1 do
local as=ar*aq*4

for at=0,aq-1 do
local au=as+at*4
local av=buffer.readu32(al,at*4)
local aw=buffer.readu32(am,au)

local ax=(av*aw)%ap

buffer.writeu32(an,au,ax)
end
end
end

function ak.InfinityNorm(al:buffer,am:number):number
local an=0
local ao=math.floor(af/2)
local ap=af
local aq=ag

for ar=0,am-1 do
local as=ar*aq*4

for at=0,aq-1 do
local au=as+at*4
local av=buffer.readu32(al,au)

local aw=if av>ao then(if av==0 then 0 else ap-av)else av
if aw>an then
an=aw
end
end
end

return an
end

function ak.MakeHint(al:buffer,am:buffer,an:buffer,ao:number,ap:number)
local aq=bit32.rshift(ap,1)
local ar=af-1

local as=ag
local at=af

for au=0,ao-1 do
local av=au*as*4

for aw=0,as-1 do
local ax=av+aw*4
local ay=buffer.readu32(al,ax)
local az=buffer.readu32(am,ax)

local aA=az+aq-1
local aB=math.floor(aA/ap)
local aC=aB*ap
local aD=if az>=aC then az-aC else az-aC+at
local aE=if az>=aD then az-aD else az-aD+at
local aF=(aE==ar)
local aG=if aF then 0 else aB

local aH=az+ay
aH=if aH>=at then aH-at else aH

local aI=aH+aq-1
local aJ=math.floor(aI/ap)
local aK=aJ*ap
local aL=if aH>=aK then aH-aK else aH-aK+at
local aM=if aH>=aL then aH-aL else aH-aL+at
local aN=(aM==ar)
local aO=if aN then 0 else aJ

local aP=if aG~=aO then 1 else 0
buffer.writeu32(an,ax,aP)
end
end
end

function ak.UseHint(al:buffer,am:buffer,an:buffer,ao:number,ap:number)
local aq=math.floor((af-1)/ap)
local ar=bit32.rshift(ap,1)
local as=af-ar
local at=af-1
local au=af

for av=0,ao-1 do
local aw=av*ag*4

for ax=0,ag-1 do
local ay=aw+ax*4
local az=buffer.readu32(al,ay)
local aA=buffer.readu32(am,ay)

local aB=aA+ar-1
local aC=math.floor(aB/ap)
local aD=aC*ap

local aE=if aA>=aD then aA-aD else aA-aD+au

local aF=if aA>=aE then aA-aE else aA-aE+au
local aG=(aF==at)

local aH=if aG then 0 else aC
local aI=if aG then(if aE>=1 then aE-1 else aE-1+au)else aE

if az==1 then
if aI>0 and aI<as then
aH+=1
else
aH-=1
end
end

buffer.writeu32(an,ay,(aH%aq+aq)%aq)
end
end
end

function ak.Count1s(al:buffer,am:number):number
local an=0

for ao=0,am*ag-1 do
local ap=buffer.readu32(al,ao*4)
an+=ap
end

return an
end

function ak.LeftShift(al:buffer,am:number,an:number)
local ao=ag
local ap=af

for aq=0,am-1 do
local ar=aq*ao*4

for as=0,ao-1 do
local at=ar+as*4
local au=buffer.readu32(al,at)

local av=bit32.lshift(au,an)
local aw=if av>=ap then av%ap else av

buffer.writeu32(al,at,aw)
end
end
end

function ak.Copy(al:buffer,am:buffer,an:number)
buffer.copy(am,0,al,0,an*ag*4)
end

return ak end function a.Y():typeof(__modImpl())local aa=a.cache.Y if not aa then aa={c=__modImpl()}a.cache.Y=aa end return aa.c end end do local function __modImpl()



















local aa=168
local ab=136

local ac=buffer.create(100)
local ad=buffer.create(100)
local ae=0

local af=buffer.create(100)
local ag=buffer.create(100)
local ah=0

local ai=buffer.create(aa)
local aj=buffer.create(ab)

local ak=buffer.create(aa)
local al=buffer.create(ab)

local am=buffer.create(168)
local an=buffer.create(128)
local ao=buffer.create(192)

local ap,aq=buffer.create(96),buffer.create(96)do
local ar=0
local as=29
local function GetNextBit():number
local at=as%2
as=bit32.bxor((as-at)//2,142*at)
return at
end

for at=0,23 do
local au=0
local av:number

for aw=1,6 do
av=if av then av*av*2 else 1
au+=GetNextBit()*av
end

local aw=GetNextBit()*av
buffer.writeu32(aq,at*4,aw)
buffer.writeu32(ap,at*4,au+aw*ar)
end
end

local function Keccak(ar:buffer,as:buffer,at:buffer,au:number,av:number,aw:number):()
local ax=aw//8
local ay,az=aq,ap

for aA=au,au+av-1,aw do
for aB=0,(ax-1)*4,4 do
local aC=aA+aB*2

buffer.writeu32(ar,aB,bit32.bxor(
buffer.readu32(ar,aB),
buffer.readu32(at,aC)
))

buffer.writeu32(as,aB,bit32.bxor(
buffer.readu32(as,aB),
buffer.readu32(at,aC+4)
))
end

local aB,aC=buffer.readu32(ar,0),buffer.readu32(as,0)
local aD,aE=buffer.readu32(ar,4),buffer.readu32(as,4)
local aF,aG=buffer.readu32(ar,8),buffer.readu32(as,8)

local aH,aI=buffer.readu32(ar,12),buffer.readu32(as,12)
local aJ,aK=buffer.readu32(ar,16),buffer.readu32(as,16)
local aL,aM=buffer.readu32(ar,20),buffer.readu32(as,20)

local aN,aO=buffer.readu32(ar,24),buffer.readu32(as,24)
local aP,aQ=buffer.readu32(ar,28),buffer.readu32(as,28)
local aR,aS=buffer.readu32(ar,32),buffer.readu32(as,32)

local aT,aU=buffer.readu32(ar,36),buffer.readu32(as,36)
local aV,b=buffer.readu32(ar,40),buffer.readu32(as,40)
local c,d=buffer.readu32(ar,44),buffer.readu32(as,44)

local e,f=buffer.readu32(ar,48),buffer.readu32(as,48)
local g,h=buffer.readu32(ar,52),buffer.readu32(as,52)
local i,j=buffer.readu32(ar,56),buffer.readu32(as,56)

local k,l=buffer.readu32(ar,60),buffer.readu32(as,60)
local m,n=buffer.readu32(ar,64),buffer.readu32(as,64)
local o,p=buffer.readu32(ar,68),buffer.readu32(as,68)

local q,r=buffer.readu32(ar,72),buffer.readu32(as,72)
local s,t=buffer.readu32(ar,76),buffer.readu32(as,76)
local u,v=buffer.readu32(ar,80),buffer.readu32(as,80)

local w,x=buffer.readu32(ar,84),buffer.readu32(as,84)
local y,z=buffer.readu32(ar,88),buffer.readu32(as,88)
local A,B=buffer.readu32(ar,92),buffer.readu32(as,92)

local C,D=buffer.readu32(ar,96),buffer.readu32(as,96)

for E=0,92,4 do
local F,G=bit32.bxor(aB,aL,aV,k,u),bit32.bxor(aC,aM,b,l,v)
local H,I=bit32.bxor(aD,aN,c,m,w),bit32.bxor(aE,aO,d,n,x)
local J,K=bit32.bxor(aF,aP,e,o,y),bit32.bxor(aG,aQ,f,p,z)
local L,M=bit32.bxor(aH,aR,g,q,A),bit32.bxor(aI,aS,h,r,B)
local N,O=bit32.bxor(aJ,aT,i,s,C),bit32.bxor(aK,aU,j,t,D)

local P,Q=bit32.bxor(F,J*2+K//2147483648),bit32.bxor(G,K*2+J//2147483648)
local R,S=bit32.bxor(P,aD),bit32.bxor(Q,aE)
local T,U=bit32.bxor(P,aN),bit32.bxor(Q,aO)
local V,W=bit32.bxor(P,c),bit32.bxor(Q,d)
local X,Y=bit32.bxor(P,m),bit32.bxor(Q,n)
local Z,_=bit32.bxor(P,w),bit32.bxor(Q,x)

aD=T//1048576+(U*4096);aE=U//1048576+(T*4096)
aN=X//524288+(Y*8192);aO=Y//524288+(X*8192)
c=R*2+S//2147483648;d=S*2+R//2147483648
m=V*1024+W//4194304;n=W*1024+V//4194304
w=Z*4+_//1073741824;x=_*4+Z//1073741824

P=bit32.bxor(H,L*2+M//2147483648);Q=bit32.bxor(I,M*2+L//2147483648)
R=bit32.bxor(P,aF);S=bit32.bxor(Q,aG)
T=bit32.bxor(P,aP);U=bit32.bxor(Q,aQ)
V=bit32.bxor(P,e);W=bit32.bxor(Q,f)
X=bit32.bxor(P,o);Y=bit32.bxor(Q,p)
Z=bit32.bxor(P,y);_=bit32.bxor(Q,z)

aF=V//2097152+(W*2048);aG=W//2097152+(V*2048)
aP=Z//8+bit32.bor(_*536870912,0);aQ=_//8+bit32.bor(Z*536870912,0)
e=T*64+U//67108864;f=U*64+T//67108864
o=(X*32768)+Y//131072;p=(Y*32768)+X//131072
y=R//4+bit32.bor(S*1073741824,0);z=S//4+bit32.bor(R*1073741824,0)

P=bit32.bxor(J,N*2+O//2147483648);Q=bit32.bxor(K,O*2+N//2147483648)
R=bit32.bxor(P,aH);S=bit32.bxor(Q,aI)
T=bit32.bxor(P,aR);U=bit32.bxor(Q,aS)
V=bit32.bxor(P,g);W=bit32.bxor(Q,h)
X=bit32.bxor(P,q);Y=bit32.bxor(Q,r)
Z=bit32.bxor(P,A);_=bit32.bxor(Q,B)

aH=bit32.bor(X*2097152,0)+Y//2048;aI=bit32.bor(Y*2097152,0)+X//2048
aR=bit32.bor(R*268435456,0)+S//16;aS=bit32.bor(S*268435456,0)+R//16
g=bit32.bor(V*33554432,0)+W//128;h=bit32.bor(W*33554432,0)+V//128
q=Z//256+bit32.bor(_*16777216,0);r=_//256+bit32.bor(Z*16777216,0)
A=T//512+bit32.bor(U*8388608,0);B=U//512+bit32.bor(T*8388608,0)
P=bit32.bxor(L,F*2+G//2147483648);Q=bit32.bxor(M,G*2+F//2147483648)

R=bit32.bxor(P,aJ);S=bit32.bxor(Q,aK)
T=bit32.bxor(P,aT);U=bit32.bxor(Q,aU)
V=bit32.bxor(P,i);W=bit32.bxor(Q,j)
X=bit32.bxor(P,s);Y=bit32.bxor(Q,t)
Z=bit32.bxor(P,C);_=bit32.bxor(Q,D)

aJ=(Z*16384)+_//262144;aK=(_*16384)+Z//262144
aT=bit32.bor(T*1048576,0)+U//4096;aU=bit32.bor(U*1048576,0)+T//4096
i=X*256+Y//16777216;j=Y*256+X//16777216
s=bit32.bor(R*134217728,0)+S//32;t=bit32.bor(S*134217728,0)+R//32
C=V//33554432+W*128;D=W//33554432+V*128

P=bit32.bxor(N,H*2+I//2147483648);Q=bit32.bxor(O,I*2+H//2147483648)
T=bit32.bxor(P,aL);U=bit32.bxor(Q,aM)
V=bit32.bxor(P,aV);W=bit32.bxor(Q,b)
X=bit32.bxor(P,k);Y=bit32.bxor(Q,l)
Z=bit32.bxor(P,u);_=bit32.bxor(Q,v)
aL=V*8+W//536870912;aM=W*8+V//536870912
aV=(Z*262144)+_//16384;b=(_*262144)+Z//16384
k=T//268435456+U*16;l=U//268435456+T*16
u=X//8388608+Y*512;v=Y//8388608+X*512
aB=bit32.bxor(P,aB);aC=bit32.bxor(Q,aC)

aB,aD,aF,aH,aJ=bit32.bxor(aB,bit32.band(-1-aD,aF)),bit32.bxor(aD,bit32.band(-1-aF,aH)),bit32.bxor(aF,bit32.band(-1-aH,aJ)),bit32.bxor(aH,bit32.band(-1-aJ,aB)),bit32.bxor(aJ,bit32.band(-1-aB,aD))::number
aC,aE,aG,aI,aK=bit32.bxor(aC,bit32.band(-1-aE,aG)),bit32.bxor(aE,bit32.band(-1-aG,aI)),bit32.bxor(aG,bit32.band(-1-aI,aK)),bit32.bxor(aI,bit32.band(-1-aK,aC)),bit32.bxor(aK,bit32.band(-1-aC,aE))::number
aL,aN,aP,aR,aT=bit32.bxor(aR,bit32.band(-1-aT,aL)),bit32.bxor(aT,bit32.band(-1-aL,aN)),bit32.bxor(aL,bit32.band(-1-aN,aP)),bit32.bxor(aN,bit32.band(-1-aP,aR)),bit32.bxor(aP,bit32.band(-1-aR,aT))::number
aM,aO,aQ,aS,aU=bit32.bxor(aS,bit32.band(-1-aU,aM)),bit32.bxor(aU,bit32.band(-1-aM,aO)),bit32.bxor(aM,bit32.band(-1-aO,aQ)),bit32.bxor(aO,bit32.band(-1-aQ,aS)),bit32.bxor(aQ,bit32.band(-1-aS,aU))::number
aV,c,e,g,i=bit32.bxor(c,bit32.band(-1-e,g)),bit32.bxor(e,bit32.band(-1-g,i)),bit32.bxor(g,bit32.band(-1-i,aV)),bit32.bxor(i,bit32.band(-1-aV,c)),bit32.bxor(aV,bit32.band(-1-c,e))::number
b,d,f,h,j=bit32.bxor(d,bit32.band(-1-f,h)),bit32.bxor(f,bit32.band(-1-h,j)),bit32.bxor(h,bit32.band(-1-j,b)),bit32.bxor(j,bit32.band(-1-b,d)),bit32.bxor(b,bit32.band(-1-d,f))::number
k,m,o,q,s=bit32.bxor(s,bit32.band(-1-k,m)),bit32.bxor(k,bit32.band(-1-m,o)),bit32.bxor(m,bit32.band(-1-o,q)),bit32.bxor(o,bit32.band(-1-q,s)),bit32.bxor(q,bit32.band(-1-s,k))::number
l,n,p,r,t=bit32.bxor(t,bit32.band(-1-l,n)),bit32.bxor(l,bit32.band(-1-n,p)),bit32.bxor(n,bit32.band(-1-p,r)),bit32.bxor(p,bit32.band(-1-r,t)),bit32.bxor(r,bit32.band(-1-t,l))::number
u,w,y,A,C=bit32.bxor(y,bit32.band(-1-A,C)),bit32.bxor(A,bit32.band(-1-C,u)),bit32.bxor(C,bit32.band(-1-u,w)),bit32.bxor(u,bit32.band(-1-w,y)),bit32.bxor(w,bit32.band(-1-y,A))::number
v,x,z,B,D=bit32.bxor(z,bit32.band(-1-B,D)),bit32.bxor(B,bit32.band(-1-D,v)),bit32.bxor(D,bit32.band(-1-v,x)),bit32.bxor(v,bit32.band(-1-x,z)),bit32.bxor(x,bit32.band(-1-z,B))::number

aB=bit32.bxor(aB,buffer.readu32(az,E))
aC=bit32.bxor(aC,buffer.readu32(ay,E))
end

buffer.writeu32(ar,0,aB);buffer.writeu32(as,0,aC)
buffer.writeu32(ar,4,aD);buffer.writeu32(as,4,aE)
buffer.writeu32(ar,8,aF);buffer.writeu32(as,8,aG)
buffer.writeu32(ar,12,aH);buffer.writeu32(as,12,aI)
buffer.writeu32(ar,16,aJ);buffer.writeu32(as,16,aK)
buffer.writeu32(ar,20,aL);buffer.writeu32(as,20,aM)
buffer.writeu32(ar,24,aN);buffer.writeu32(as,24,aO)
buffer.writeu32(ar,28,aP);buffer.writeu32(as,28,aQ)
buffer.writeu32(ar,32,aR);buffer.writeu32(as,32,aS)
buffer.writeu32(ar,36,aT);buffer.writeu32(as,36,aU)
buffer.writeu32(ar,40,aV);buffer.writeu32(as,40,b)
buffer.writeu32(ar,44,c);buffer.writeu32(as,44,d)
buffer.writeu32(ar,48,e);buffer.writeu32(as,48,f)
buffer.writeu32(ar,52,g);buffer.writeu32(as,52,h)
buffer.writeu32(ar,56,i);buffer.writeu32(as,56,j)
buffer.writeu32(ar,60,k);buffer.writeu32(as,60,l)
buffer.writeu32(ar,64,m);buffer.writeu32(as,64,n)
buffer.writeu32(ar,68,o);buffer.writeu32(as,68,p)
buffer.writeu32(ar,72,q);buffer.writeu32(as,72,r)
buffer.writeu32(ar,76,s);buffer.writeu32(as,76,t)
buffer.writeu32(ar,80,u);buffer.writeu32(as,80,v)
buffer.writeu32(ar,84,w);buffer.writeu32(as,84,x)
buffer.writeu32(ar,88,y);buffer.writeu32(as,88,z)
buffer.writeu32(ar,92,A);buffer.writeu32(as,92,B)
buffer.writeu32(ar,96,C);buffer.writeu32(as,96,D)
end
end

local ar={}

function ar.Reset128()
buffer.fill(ac,0,0,100)
buffer.fill(ad,0,0,100)
ae=0
end

function ar.Reset256()
buffer.fill(af,0,0,100)
buffer.fill(ag,0,0,100)
ah=0
end

function ar.Absorb128(as:buffer)
local at=buffer.len(as)
local au=aa

local av=ak
buffer.fill(av,0,0,au)

if at>0 then
buffer.copy(av,0,as,0,at)
end

if au-at==1 then
buffer.writeu8(av,at,0x9F)
else
buffer.writeu8(av,at,0x1F)
buffer.writeu8(av,au-1,0x80)
end

Keccak(ac,ad,av,0,au,au)
end

function ar.Absorb256(as:buffer)
local at=buffer.len(as)
local au=ab

local av=al
buffer.fill(av,0,0,au)

if at>0 then
buffer.copy(av,0,as,0,at)
end

if au-at==1 then
buffer.writeu8(av,at,0x9F)
else
buffer.writeu8(av,at,0x1F)
buffer.writeu8(av,au-1,0x80)
end

Keccak(af,ag,av,0,au,au)
end

function ar.Squeeze128Into(as:buffer,at:number,au:number?)
local av=au or 0
local aw=aa
local ax=ac
local ay=ad
local az=ae
local aA=ai

local aB=0
while aB<at do
if az>=aw then
Keccak(ax,ay,aA,0,aw,aw)
az=0
end

local aC=aw-az
if aC>at-aB then
aC=at-aB
end

local aD=0
while aD<aC do
local aE=az+aD
local aF=bit32.rshift(aE,3)
local aG=bit32.band(aE,7)
local aH=bit32.lshift(aF,2)

if aG==0 and aD+8<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
buffer.writeu32(as,av+aB+aD+4,buffer.readu32(ay,aH))
aD+=8
elseif aG==0 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
aD+=4
elseif aG==4 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ay,aH))
aD+=4
else
local aI
if aG<4 then
aI=bit32.extract(buffer.readu32(ax,aH),bit32.lshift(aG,3),8)
else
aI=bit32.extract(buffer.readu32(ay,aH),bit32.lshift(aG-4,3),8)
end
buffer.writeu8(as,av+aB+aD,aI)
aD+=1
end
end

aB+=aC
az+=aC
end

ae=az
end

function ar.Squeeze128(as:number):buffer
local at=if as==168 then am else buffer.create(as)
ar.Squeeze128Into(at,as,0)
return at
end

function ar.Squeeze256Into(as:buffer,at:number,au:number?)
local av=au or 0
local aw=ab
local ax=af
local ay=ag
local az=ah
local aA=aj

local aB=0
while aB<at do
if az>=aw then
Keccak(ax,ay,aA,0,aw,aw)
az=0
end

local aC=aw-az
if aC>at-aB then
aC=at-aB
end

local aD=0
while aD<aC do
local aE=az+aD
local aF=bit32.rshift(aE,3)
local aG=bit32.band(aE,7)
local aH=bit32.lshift(aF,2)

if aG==0 and aD+8<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
buffer.writeu32(as,av+aB+aD+4,buffer.readu32(ay,aH))
aD+=8
elseif aG==0 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
aD+=4
elseif aG==4 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ay,aH))
aD+=4
else
local aI
if aG<4 then
aI=bit32.extract(buffer.readu32(ax,aH),bit32.lshift(aG,3),8)
else
aI=bit32.extract(buffer.readu32(ay,aH),bit32.lshift(aG-4,3),8)
end
buffer.writeu8(as,av+aB+aD,aI)
aD+=1
end
end

aB+=aC
az+=aC
end

ah=az
end

function ar.Squeeze256(as:number):buffer
local at=if as==128 then an
elseif as==192 then ao
else buffer.create(as)
ar.Squeeze256Into(at,as,0)
return at
end

return ar end function a.Z():typeof(__modImpl())local aa=a.cache.Z if not aa then aa={c=__modImpl()}a.cache.Z=aa end return aa.c end end do local function __modImpl()
















local aa=8380417

local ab={}

function ab.CheckEta(ac:number):boolean
return ac==2 or ac==4
end

function ab.CheckNonce(ac:number):boolean
return ac==0 or ac==4 or ac==5 or ac==7
end

function ab.CheckGamma1(ac:number):boolean
return ac==bit32.lshift(1,17)or ac==bit32.lshift(1,19)
end

function ab.CheckGamma2(ac:number):boolean
return ac==math.floor((aa-1)/88)or ac==math.floor((aa-1)/32)
end

function ab.CheckTau(ac:number):boolean
return ac==39 or ac==49 or ac==60
end

function ab.CheckD(ac:number):boolean
return ac==13
end

function ab.CheckKeygenParams(ac:number,ad:number,ae:number,af:number):boolean
return(ac==4 and ad==4 and ae==13 and af==2)or
(ac==6 and ad==5 and ae==13 and af==4)or
(ac==8 and ad==7 and ae==13 and af==2)
end

function ab.CheckSigningParams(ac:number,ad:number,ae:number,af:number,ag:number,ah:number,ai:number,aj:number,ak:number,al:number):boolean
return(ac==4 and ad==4 and ae==13 and af==2 and
ag==bit32.lshift(1,17)and
ah==math.floor((aa-1)/88)and
ai==39 and aj==ai*af and ak==80 and al==128)or
(ac==6 and ad==5 and ae==13 and af==4 and
ag==bit32.lshift(1,19)and
ah==math.floor((aa-1)/32)and
ai==49 and aj==ai*af and ak==55 and al==192)or
(ac==8 and ad==7 and ae==13 and af==2 and
ag==bit32.lshift(1,19)and
ah==math.floor((aa-1)/32)and
ai==60 and aj==ai*af and ak==75 and al==256)
end

function ab.CheckVerifyParams(ac:number,ad:number,ae:number,af:number,ag:number,ah:number,ai:number,aj:number,ak:number):boolean
return(ac==4 and ad==4 and ae==13 and
af==bit32.lshift(1,17)and
ag==math.floor((aa-1)/88)and
ah==39 and ai==ah*2 and aj==80 and ak==128)or
(ac==6 and ad==5 and ae==13 and
af==bit32.lshift(1,19)and
ag==math.floor((aa-1)/32)and
ah==49 and ai==ah*4 and aj==55 and ak==192)or
(ac==8 and ad==7 and ae==13 and
af==bit32.lshift(1,19)and
ag==math.floor((aa-1)/32)and
ah==60 and ai==ah*2 and aj==75 and ak==256)
end

return ab end function a._():typeof(__modImpl())local aa=a.cache._ if not aa then aa={c=__modImpl()}a.cache._=aa end return aa.c end end do local function __modImpl()















local aa=a.Z()
local ab=a._()

local ac=256
local ad=8380417

local ae={}

local af=buffer.create(34)
local ag=buffer.create(66)

function ae.ExpandA(ah:buffer,ai:buffer,aj:number,ak:number)
buffer.copy(af,0,ah,0,32)

local al=af
local am=ac
local an=ad
local ao=aa

for ap=0,aj-1 do
for aq=0,ak-1 do
local ar=(ap*ak+aq)*am*4

buffer.writeu8(al,32,aq)
buffer.writeu8(al,33,ap)

ao.Reset128()
ao.Absorb128(al)

local as=0
local at=504

while as<am do
local au=ao.Squeeze128(at)
local av=0
local aw=buffer.len(au)

while as<am and av+5<aw do
local ax=buffer.readu32(au,av)
local ay=buffer.readu8(au,av+4)
local az=buffer.readu8(au,av+5)

local aA=bit32.band(ax,0x7FFFFF)
if aA<an then
buffer.writeu32(ai,ar+as*4,aA)
as+=1
end

local aB=bit32.bor(
bit32.rshift(ax,24),
bit32.lshift(ay,8),
bit32.lshift(bit32.band(az,0x7F),16)
)
if aB<an and as<am then
buffer.writeu32(ai,ar+as*4,aB)
as+=1
end

av+=6
end

while as<am and av+2<aw do
local ax=bit32.band(buffer.readu8(au,av+2),0x7F)
local ay=buffer.readu8(au,av+1)
local az=buffer.readu8(au,av)

local aA=bit32.bor(
bit32.lshift(ax,16),
bit32.lshift(ay,8),
az
)

if aA<an then
buffer.writeu32(ai,ar+as*4,aA)
as+=1
end

av+=3
end
end
end
end
end

function ae.ExpandS(ah:buffer,ai:buffer,aj:number,ak:number,al:number)
if not ab.CheckEta(aj)or not ab.CheckNonce(al)then
error"Invalid parameters for ExpandS"
end

buffer.copy(ag,0,ah,0,64)

local am=ag
local an=ac
local ao=ad

for ap=0,ak-1 do
local aq=ap*an*4
local ar=al+ap

buffer.writeu8(am,64,bit32.band(ar,0xFF))
buffer.writeu8(am,65,bit32.band(bit32.rshift(ar,8),0xFF))

aa.Reset256()
aa.Absorb256(am)

local as=0
local at=if aj==2 then 136 else 272

while as<an do
local au=aa.Squeeze256(at)
local av=0
local aw=buffer.len(au)

if aj==2 then
while as<an and av+3<aw do
local ax=buffer.readu32(au,av)

local ay=bit32.band(ax,0x0F)
local az=bit32.band(bit32.rshift(ax,4),0x0F)
local aA=bit32.band(bit32.rshift(ax,8),0x0F)
local aB=bit32.band(bit32.rshift(ax,12),0x0F)
local aC=bit32.band(bit32.rshift(ax,16),0x0F)
local aD=bit32.band(bit32.rshift(ax,20),0x0F)
local aE=bit32.band(bit32.rshift(ax,24),0x0F)
local aF=bit32.band(bit32.rshift(ax,28),0x0F)

if ay<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(ay%5)+(if(ay%5)>2 then ao else 0))
as+=1
end
if az<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(az%5)+(if(az%5)>2 then ao else 0))
as+=1
end
if aA<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(aA%5)+(if(aA%5)>2 then ao else 0))
as+=1
end
if aB<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(aB%5)+(if(aB%5)>2 then ao else 0))
as+=1
end
if aC<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(aC%5)+(if(aC%5)>2 then ao else 0))
as+=1
end
if aD<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(aD%5)+(if(aD%5)>2 then ao else 0))
as+=1
end
if aE<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(aE%5)+(if(aE%5)>2 then ao else 0))
as+=1
end
if aF<15 and as<an then
buffer.writeu32(ai,aq+as*4,2-(aF%5)+(if(aF%5)>2 then ao else 0))
as+=1
end

av+=4
end
else
while as<an and av+3<aw do
local ax=buffer.readu32(au,av)

local ay=bit32.band(ax,0x0F)
local az=bit32.band(bit32.rshift(ax,4),0x0F)
local aA=bit32.band(bit32.rshift(ax,8),0x0F)
local aB=bit32.band(bit32.rshift(ax,12),0x0F)
local aC=bit32.band(bit32.rshift(ax,16),0x0F)
local aD=bit32.band(bit32.rshift(ax,20),0x0F)
local aE=bit32.band(bit32.rshift(ax,24),0x0F)
local aF=bit32.band(bit32.rshift(ax,28),0x0F)

if ay<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-ay+(if ay>4 then ao else 0))
as+=1
end
if az<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-az+(if az>4 then ao else 0))
as+=1
end
if aA<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-aA+(if aA>4 then ao else 0))
as+=1
end
if aB<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-aB+(if aB>4 then ao else 0))
as+=1
end
if aC<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-aC+(if aC>4 then ao else 0))
as+=1
end
if aD<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-aD+(if aD>4 then ao else 0))
as+=1
end
if aE<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-aE+(if aE>4 then ao else 0))
as+=1
end
if aF<9 and as<an then
buffer.writeu32(ai,aq+as*4,4-aF+(if aF>4 then ao else 0))
as+=1
end

av+=4
end
end

while as<an and av<aw do
local ax=buffer.readu8(au,av)
local ay=bit32.band(ax,0x0F)
local az=bit32.band(bit32.rshift(ax,4),0x0F)

if aj==2 then
if ay<15 then
buffer.writeu32(ai,aq+as*4,2-(ay%5)+(if(ay%5)>2 then ao else 0))
as+=1
end
if as<an and az<15 then
buffer.writeu32(ai,aq+as*4,2-(az%5)+(if(az%5)>2 then ao else 0))
as+=1
end
else
if ay<9 then
buffer.writeu32(ai,aq+as*4,4-ay+(if ay>4 then ao else 0))
as+=1
end
if as<an and az<9 then
buffer.writeu32(ai,aq+as*4,4-az+(if az>4 then ao else 0))
as+=1
end
end

av+=1
end
end
end
end

function ae.ExpandMask(ah:buffer,ai:number,aj:buffer,ak:number,al:number)
if not ab.CheckGamma1(ak)then
error"Invalid Gamma1 parameter"
end

local am=if ak==131072 then 18 else 20
local an=math.floor((ac*am)/8)

buffer.copy(ag,0,ah,0,64)

local ao=ag
local ap=ac
local aq=ad
local ar=ak

for as=0,al-1 do
local at=as*ap*4
local au=ai+as

buffer.writeu8(ao,64,bit32.band(au,0xFF))
buffer.writeu8(ao,65,bit32.band(bit32.rshift(au,8),0xFF))

aa.Reset256()
aa.Absorb256(ao)

local av=aa.Squeeze256(an)

if am==18 then
for aw=0,63 do
local ax=aw*9
local ay=at+aw*16

local az=buffer.readu8(av,ax+0)
local aA=buffer.readu8(av,ax+1)
local aB=buffer.readu8(av,ax+2)
local aC=buffer.readu8(av,ax+3)
local aD=buffer.readu8(av,ax+4)
local aE=buffer.readu8(av,ax+5)
local aF=buffer.readu8(av,ax+6)
local aG=buffer.readu8(av,ax+7)
local aH=buffer.readu8(av,ax+8)

local aI=bit32.bor(az,bit32.lshift(aA,8),bit32.lshift(bit32.band(aB,0x3),16))
local aJ=bit32.bor(bit32.rshift(aB,2),bit32.lshift(aC,6),bit32.lshift(bit32.band(aD,0xF),14))
local aK=bit32.bor(bit32.rshift(aD,4),bit32.lshift(aE,4),bit32.lshift(bit32.band(aF,0x3F),12))
local aL=bit32.bor(bit32.rshift(aF,6),bit32.lshift(aG,2),bit32.lshift(aH,10))

local aM=ar-aI
local aN=ar-aJ
local aO=ar-aK
local aP=ar-aL

buffer.writeu32(aj,ay+0,if aM<0 then aM+aq else aM)
buffer.writeu32(aj,ay+4,if aN<0 then aN+aq else aN)
buffer.writeu32(aj,ay+8,if aO<0 then aO+aq else aO)
buffer.writeu32(aj,ay+12,if aP<0 then aP+aq else aP)
end
else
for aw=0,63 do
local ax=aw*10
local ay=at+aw*16

local az=buffer.readu8(av,ax+0)
local aA=buffer.readu8(av,ax+1)
local aB=buffer.readu8(av,ax+2)
local aC=buffer.readu8(av,ax+3)
local aD=buffer.readu8(av,ax+4)
local aE=buffer.readu8(av,ax+5)
local aF=buffer.readu8(av,ax+6)
local aG=buffer.readu8(av,ax+7)
local aH=buffer.readu8(av,ax+8)
local aI=buffer.readu8(av,ax+9)

local aJ=bit32.bor(az,bit32.lshift(aA,8),bit32.lshift(bit32.band(aB,0xF),16))
local aK=bit32.bor(bit32.rshift(aB,4),bit32.lshift(aC,4),bit32.lshift(aD,12))
local aL=bit32.bor(aE,bit32.lshift(aF,8),bit32.lshift(bit32.band(aG,0xF),16))
local aM=bit32.bor(bit32.rshift(aG,4),bit32.lshift(aH,4),bit32.lshift(aI,12))

local aN=ar-aJ
local aO=ar-aK
local aP=ar-aL
local aQ=ar-aM

buffer.writeu32(aj,ay+0,if aN<0 then aN+aq else aN)
buffer.writeu32(aj,ay+4,if aO<0 then aO+aq else aO)
buffer.writeu32(aj,ay+8,if aP<0 then aP+aq else aP)
buffer.writeu32(aj,ay+12,if aQ<0 then aQ+aq else aQ)
end
end
end
end

function ae.SampleInBall(ah:buffer,ai:buffer,aj:number,ak:number)
if not ab.CheckTau(aj)then
error"Invalid Tau parameter"
end

buffer.fill(ai,0,0,ac*4)

aa.Reset256()
aa.Absorb256(ah)

local al=aa.Squeeze256(8)
local am=buffer.readu32(al,0)
local an=buffer.readu32(al,4)

local ao=ac-aj
local ap=ao
local aq=136
local ar=ad

while ap<ac do
local as=aa.Squeeze256(aq)
local at=0
local au=buffer.len(as)

while ap<ac and at+3<au do
local av=buffer.readu32(as,at)

for aw=0,3 do
if ap>=ac then break end

local ax=bit32.band(bit32.rshift(av,aw*8),0xFF)

if ax<=ap then
local ay=ap-ao
local az
if ay<32 then
az=bit32.band(bit32.rshift(am,ay),1)
else
az=bit32.band(bit32.rshift(an,ay-32),1)
end

buffer.writeu32(ai,ap*4,buffer.readu32(ai,ax*4))
buffer.writeu32(ai,ax*4,if az==0 then 1 else ar-1)

ap+=1
end
end

at+=4
end

while ap<ac and at<au do
local av=buffer.readu8(as,at)

if av<=ap then
local aw=ap-ao
local ax
if aw<32 then
ax=bit32.band(bit32.rshift(am,aw),1)
else
ax=bit32.band(bit32.rshift(an,aw-32),1)
end

buffer.writeu32(ai,ap*4,buffer.readu32(ai,av*4))
buffer.writeu32(ai,av*4,if ax==0 then 1 else ar-1)

ap+=1
end

at+=1
end
end
end

return ae end function a.aa():typeof(__modImpl())local aa=a.cache.aa if not aa then aa={c=__modImpl()}a.cache.aa=aa end return aa.c end end do local function __modImpl()

















local aa=23

local ab={}

local function BitWidth(ac:number):number
if ac==0 then
return 0
end

local ad=0
local ae=ac

while ae>0 do
ad+=1
ae=bit32.rshift(ae,1)
end

return ad
end

function ab.PubKeyLen(ac:number,ad:number):number
local ae=aa-ad
local af=32+ac*32*ae

return af
end

function ab.SecKeyLen(ac:number,ad:number,ae:number,af:number):number
local ag=BitWidth(2*ae)
local ah=128+32*(ag*(ac+ad)+ac*af)

return ah
end

function ab.SigLen(ac:number,ad:number,ae:number,af:number,ag:number):number
local ah=BitWidth(ae)
local ai=math.floor((2*ag)/8)+(32*ad*ah)+(af+ac)

return ai
end

function ab.BitWidth(ac:number):number
return BitWidth(ac)
end

return ab end function a.ab():typeof(__modImpl())local aa=a.cache.ab if not aa then aa={c=__modImpl()}a.cache.ab=aa end return aa.c end end do local function __modImpl()













local aa=buffer.create(512)do
local ab="0123456789abcdef"
for ac=0,255 do
local ad=bit32.rshift(ac,4)
local ae=ac%16

local af=string.byte(ab,ad+1)
local ag=string.byte(ab,ae+1)

local ah=af+bit32.lshift(ag,8)
buffer.writeu16(aa,ac*2,ah)
end
end

local ab=buffer.create(131072)do
for ac=0,255 do
for ad=0,255 do
local ae=0
local af=0

if ac>=48 and ac<=57 then
ae=ac-48
elseif ac>=65 and ac<=70 then
ae=ac-55
elseif ac>=97 and ac<=102 then
ae=ac-87
else
ae=0
end

if ad>=48 and ad<=57 then
af=ad-48
elseif ad>=65 and ad<=70 then
af=ad-55
elseif ad>=97 and ad<=102 then
af=ad-87
else
af=0
end

local ag=bit32.lshift(ae,4)+af
local ah=bit32.lshift(ad,8)+ac
buffer.writeu16(ab,ah*2,ag)
end
end
end

local ac={}

function ac.ToHex(ad:buffer):string
local ae=buffer.len(ad)
local af=buffer.create(ae*2)

local ag=aa

local ah=ae%8
local ai=0

for aj=0,ae-ah-1,8 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
local al=buffer.readu16(ag,buffer.readu8(ad,aj+1)*2)
local am=buffer.readu16(ag,buffer.readu8(ad,aj+2)*2)
local an=buffer.readu16(ag,buffer.readu8(ad,aj+3)*2)
local ao=buffer.readu16(ag,buffer.readu8(ad,aj+4)*2)
local ap=buffer.readu16(ag,buffer.readu8(ad,aj+5)*2)
local aq=buffer.readu16(ag,buffer.readu8(ad,aj+6)*2)
local ar=buffer.readu16(ag,buffer.readu8(ad,aj+7)*2)

buffer.writeu16(af,ai,ak)
buffer.writeu16(af,ai+2,al)
buffer.writeu16(af,ai+4,am)
buffer.writeu16(af,ai+6,an)
buffer.writeu16(af,ai+8,ao)
buffer.writeu16(af,ai+10,ap)
buffer.writeu16(af,ai+12,aq)
buffer.writeu16(af,ai+14,ar)

ai+=16
end

for aj=ae-ah,ae-1 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
buffer.writeu16(af,ai,ak)
ai+=2
end

return buffer.tostring(af)
end

function ac.FromHex(ad:string|buffer):buffer
local ae=if type(ad)=="string"then buffer.fromstring(ad)else ad
local af=buffer.len(ae)
if af%2~=0 then
error(`Length must be even, got {af}`)
end

local ag=buffer.create(bit32.rshift(af,1))
local ah=af%16
local ai=0
local aj=ab

for ak=0,af-ah-1,16 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(ae,ak+2)
local an=buffer.readu16(ae,ak+4)
local ao=buffer.readu16(ae,ak+6)
local ap=buffer.readu16(ae,ak+8)
local aq=buffer.readu16(ae,ak+10)
local ar=buffer.readu16(ae,ak+12)
local as=buffer.readu16(ae,ak+14)

local at=buffer.readu16(aj,al*2)
local au=buffer.readu16(aj,am*2)
local av=buffer.readu16(aj,an*2)
local aw=buffer.readu16(aj,ao*2)
local ax=buffer.readu16(aj,ap*2)
local ay=buffer.readu16(aj,aq*2)
local az=buffer.readu16(aj,ar*2)
local aA=buffer.readu16(aj,as*2)

local aB=bit32.lshift(aw,24)+bit32.lshift(av,16)+
bit32.lshift(au,8)+at
local aC=bit32.lshift(aA,24)+bit32.lshift(az,16)+
bit32.lshift(ay,8)+ax

buffer.writeu32(ag,ai,aB)
buffer.writeu32(ag,ai+4,aC)
ai+=8
end

for ak=af-ah,af-1,2 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(aj,al*2)
buffer.writeu8(ag,ai,am)
ai+=1
end

return ag
end

return ac end function a.ac():typeof(__modImpl())local aa=a.cache.ac if not aa then aa={c=__modImpl()}a.cache.ac=aa end return aa.c end end do local function __modImpl()
























local aa=4
local ab=64
local ac=16

local ad=12
local ae=16
local af=32

local ag=buffer.create(16)do
local ah={string.byte("expand 32-byte k",1,-1)}
for ai,aj in ah do
buffer.writeu8(ag,ai-1,aj)
end
end

local ah=buffer.create(16)do
local ai={string.byte("expand 16-byte k",1,-1)}
for aj,ak in ai do
buffer.writeu8(ah,aj-1,ak)
end
end

local function ProcessBlock(ai:buffer,aj:number)
local ak:number,al:number,am:number,an:number,ao:number,ap:number,aq:number,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number=
buffer.readu32(ai,0),buffer.readu32(ai,4),
buffer.readu32(ai,8),buffer.readu32(ai,12),
buffer.readu32(ai,16),buffer.readu32(ai,20),
buffer.readu32(ai,24),buffer.readu32(ai,28),
buffer.readu32(ai,32),buffer.readu32(ai,36),
buffer.readu32(ai,40),buffer.readu32(ai,44),
buffer.readu32(ai,48),buffer.readu32(ai,52),
buffer.readu32(ai,56),buffer.readu32(ai,60)

for aA=1,aj do
local aB=aA%2==1

if aB then
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),16)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),12)
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),8)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),7)

al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),16)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),12)
al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),8)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),7)

am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),16)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),12)
am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),8)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),7)

an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),16)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),12)
an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),8)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),7)
else
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),16)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),12)
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),8)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),7)

al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),16)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),12)
al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),8)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),7)

am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),16)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),12)
am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),8)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),7)

an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),16)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),12)
an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),8)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),7)
end
end

buffer.writeu32(ai,0,buffer.readu32(ai,0)+ak)
buffer.writeu32(ai,4,buffer.readu32(ai,4)+al)
buffer.writeu32(ai,8,buffer.readu32(ai,8)+am)
buffer.writeu32(ai,12,buffer.readu32(ai,12)+an)
buffer.writeu32(ai,16,buffer.readu32(ai,16)+ao)
buffer.writeu32(ai,20,buffer.readu32(ai,20)+ap)
buffer.writeu32(ai,24,buffer.readu32(ai,24)+aq)
buffer.writeu32(ai,28,buffer.readu32(ai,28)+ar)
buffer.writeu32(ai,32,buffer.readu32(ai,32)+as)
buffer.writeu32(ai,36,buffer.readu32(ai,36)+at)
buffer.writeu32(ai,40,buffer.readu32(ai,40)+au)
buffer.writeu32(ai,44,buffer.readu32(ai,44)+av)
buffer.writeu32(ai,48,buffer.readu32(ai,48)+aw)
buffer.writeu32(ai,52,buffer.readu32(ai,52)+ax)
buffer.writeu32(ai,56,buffer.readu32(ai,56)+ay)
buffer.writeu32(ai,60,buffer.readu32(ai,60)+az)
end

local function InitializeState(ai:buffer,aj:buffer,ak:number):buffer
local al=buffer.len(ai)
local am=buffer.create(ac*aa)

local an=al==32 and ag or ah

buffer.copy(am,0,an,0,16)

buffer.copy(am,16,ai,0,math.min(al,16))
if al==32 then
buffer.copy(am,32,ai,16,16)
else
buffer.copy(am,32,ai,0,16)
end

buffer.writeu32(am,48,ak)
buffer.copy(am,52,aj,0,12)

return am
end

local function ChaCha20(ai:buffer,aj:buffer,ak:buffer,al:number?,am:number?):buffer
if ai==nil then
error("Data cannot be nil",2)
end

if typeof(ai)~="buffer"then
error(`Data must be a buffer, got {typeof(ai)}`,2)
end

if aj==nil then
error("Key cannot be nil",2)
end

if typeof(aj)~="buffer"then
error(`Key must be a buffer, got {typeof(aj)}`,2)
end

local an=buffer.len(aj)
if an~=ae and an~=af then
error(`Key must be {ae} or {af} bytes long, got {an} bytes`,2)
end

if ak==nil then
error("Nonce cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Nonce must be a buffer, got {typeof(ak)}`,2)
end

local ao=buffer.len(ak)
if ao~=ad then
error(`Nonce must be exactly {ad} bytes long, got {ao} bytes`,2)
end

if al then
if typeof(al)~="number"then
error(`Counter must be a number, got {typeof(al)}`,2)
end

if al<0 then
error(`Counter cannot be negative, got {al}`,2)
end

if al~=math.floor(al)then
error(`Counter must be an integer, got {al}`,2)
end

if al>=4294967296 then
error(`Counter must be less than 2^32, got {al}`,2)
end
end

if am then
if typeof(am)~="number"then
error(`Rounds must be a number, got {typeof(am)}`,2)
end

if am<=0 then
error(`Rounds must be positive, got {am}`,2)
end

if am~=math.floor(am)then
error(`Rounds must be an integer, got {am}`,2)
end

if am%2~=0 then
error(`Rounds must be even, got {am}`,2)
end
end

local ap=al or 1
local aq=am or 20

local ar=buffer.len(ai)
if ar==0 then
return buffer.create(0)
end

local as=buffer.create(ar)

local at=0

local au=InitializeState(aj,ak,ap)
local av=buffer.create(64)
buffer.copy(av,0,au,0)

while at<ar do
ProcessBlock(au,aq)

local aw=math.min(ab,ar-at)

for ax=0,aw-1 do
local ay=buffer.readu8(ai,at+ax)
local az=buffer.readu8(au,ax)
buffer.writeu8(as,at+ax,bit32.bxor(ay,az))
end

at+=aw
ap+=1
buffer.copy(au,0,av,0)
buffer.writeu32(au,48,ap)
end

return as
end

return ChaCha20 end function a.ad():typeof(__modImpl())local aa=a.cache.ad if not aa then aa={c=__modImpl()}a.cache.ad=aa end return aa.c end end do local function __modImpl()




























local aa=64
local ab=32
local ac=64
local ad=64
local ae=ad*ab

local af=0x01
local ag=0x02
local ah=0x04
local ai=0x08

local aj=buffer.create(ab)do
local ak={
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
}
for al,am in ipairs(ak)do
buffer.writeu32(aj,(al-1)*4,am)
end
end

local function Compress(ak:buffer,al:buffer,am:number,an:number,ao:number,ap:boolean?):buffer
local aq=buffer.readu32(ak,0)
local ar=buffer.readu32(ak,4)
local as=buffer.readu32(ak,8)
local at=buffer.readu32(ak,12)
local au=buffer.readu32(ak,16)
local av=buffer.readu32(ak,20)
local aw=buffer.readu32(ak,24)
local ax=buffer.readu32(ak,28)

local ay,az,aA,aB=aq,ar,as,at
local aC,aD,aE,aF=au,av,aw,ax
local aG,aH,aI,aJ=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a

local aK=am%(4294967296)
local aL=(am-aK)*(2.3283064365386963E-10)

local aM=buffer.readu32(al,0)
local aN=buffer.readu32(al,4)
local aO=buffer.readu32(al,8)
local aP=buffer.readu32(al,12)
local aQ=buffer.readu32(al,16)
local aR=buffer.readu32(al,20)
local aS=buffer.readu32(al,24)
local aT=buffer.readu32(al,28)
local aU=buffer.readu32(al,32)
local aV=buffer.readu32(al,36)
local b=buffer.readu32(al,40)
local c=buffer.readu32(al,44)
local d=buffer.readu32(al,48)
local e=buffer.readu32(al,52)
local f=buffer.readu32(al,56)
local g=buffer.readu32(al,60)

local h
for i=1,7 do
ay+=aC+aM;aK=bit32.lrotate(bit32.bxor(aK,ay),16)
aG+=aK;aC=bit32.lrotate(bit32.bxor(aC,aG),20)
ay+=aC+aN;aK=bit32.lrotate(bit32.bxor(aK,ay),24)
aG+=aK;aC=bit32.lrotate(bit32.bxor(aC,aG),25)

az+=aD+aO;aL=bit32.lrotate(bit32.bxor(aL,az),16)
aH+=aL;aD=bit32.lrotate(bit32.bxor(aD,aH),20)
az+=aD+aP;aL=bit32.lrotate(bit32.bxor(aL,az),24)
aH+=aL;aD=bit32.lrotate(bit32.bxor(aD,aH),25)

aA+=aE+aQ;an=bit32.lrotate(bit32.bxor(an,aA),16)
aI+=an;aE=bit32.lrotate(bit32.bxor(aE,aI),20)
aA+=aE+aR;an=bit32.lrotate(bit32.bxor(an,aA),24)
aI+=an;aE=bit32.lrotate(bit32.bxor(aE,aI),25)

aB+=aF+aS;ao=bit32.lrotate(bit32.bxor(ao,aB),16)
aJ+=ao;aF=bit32.lrotate(bit32.bxor(aF,aJ),20)
aB+=aF+aT;ao=bit32.lrotate(bit32.bxor(ao,aB),24)
aJ+=ao;aF=bit32.lrotate(bit32.bxor(aF,aJ),25)

ay+=aD+aU;ao=bit32.lrotate(bit32.bxor(ao,ay),16)
aI+=ao;aD=bit32.lrotate(bit32.bxor(aD,aI),20)
ay+=aD+aV;ao=bit32.lrotate(bit32.bxor(ao,ay),24)
aI+=ao;aD=bit32.lrotate(bit32.bxor(aD,aI),25)

az+=aE+b;aK=bit32.lrotate(bit32.bxor(aK,az),16)
aJ+=aK;aE=bit32.lrotate(bit32.bxor(aE,aJ),20)
az+=aE+c;aK=bit32.lrotate(bit32.bxor(aK,az),24)
aJ+=aK;aE=bit32.lrotate(bit32.bxor(aE,aJ),25)

aA+=aF+d;aL=bit32.lrotate(bit32.bxor(aL,aA),16)
aG+=aL;aF=bit32.lrotate(bit32.bxor(aF,aG),20)
aA+=aF+e;aL=bit32.lrotate(bit32.bxor(aL,aA),24)
aG+=aL;aF=bit32.lrotate(bit32.bxor(aF,aG),25)

aB+=aC+f;an=bit32.lrotate(bit32.bxor(an,aB),16)
aH+=an;aC=bit32.lrotate(bit32.bxor(aC,aH),20)
aB+=aC+g;an=bit32.lrotate(bit32.bxor(an,aB),24)
aH+=an;aC=bit32.lrotate(bit32.bxor(aC,aH),25)

if i~=7 then
h=aO
aO=aP
aP=b
b=d
d=aV
aV=c
c=aR
aR=aM
aM=h

h=aS
aS=aQ
aQ=aT
aT=e
e=f
f=g
g=aU
aU=aN
aN=h
end
end

if ap then
local i=buffer.create(ac)
buffer.writeu32(i,0,bit32.bxor(ay,aG))
buffer.writeu32(i,4,bit32.bxor(az,aH))
buffer.writeu32(i,8,bit32.bxor(aA,aI))
buffer.writeu32(i,12,bit32.bxor(aB,aJ))
buffer.writeu32(i,16,bit32.bxor(aC,aK))
buffer.writeu32(i,20,bit32.bxor(aD,aL))
buffer.writeu32(i,24,bit32.bxor(aE,an))
buffer.writeu32(i,28,bit32.bxor(aF,ao))

buffer.writeu32(i,32,bit32.bxor(aG,aq))
buffer.writeu32(i,36,bit32.bxor(aH,ar))
buffer.writeu32(i,40,bit32.bxor(aI,as))
buffer.writeu32(i,44,bit32.bxor(aJ,at))
buffer.writeu32(i,48,bit32.bxor(aK,au))
buffer.writeu32(i,52,bit32.bxor(aL,av))
buffer.writeu32(i,56,bit32.bxor(an,aw))
buffer.writeu32(i,60,bit32.bxor(ao,ax))

return i
else
local i=buffer.create(ab)
buffer.writeu32(i,0,bit32.bxor(ay,aG))
buffer.writeu32(i,4,bit32.bxor(az,aH))
buffer.writeu32(i,8,bit32.bxor(aA,aI))
buffer.writeu32(i,12,bit32.bxor(aB,aJ))
buffer.writeu32(i,16,bit32.bxor(aC,aK))
buffer.writeu32(i,20,bit32.bxor(aD,aL))
buffer.writeu32(i,24,bit32.bxor(aE,an))
buffer.writeu32(i,28,bit32.bxor(aF,ao))

return i
end
end

local function ProcessMessage(ak:buffer,al:number,am:buffer,an:number):buffer
local ao=buffer.len(am)
local ap=buffer.create(ae)
local aq=0
local ar=buffer.create(ab)
buffer.copy(ar,0,ak,0,ab)

local as=0
local at=0
local au=0
local av=af

local aw=buffer.create(aa)

for ax=0,ao-aa-1,aa do
buffer.copy(aw,0,am,ax,aa)
local ay=al+av+au

ar=Compress(ar,aw,as,aa,ay)
av=0
at+=1

if at==15 then
au=ag
elseif at==16 then
local az=ar
local aA=as+1

while aA%2==0 do
aq=aq-1
local aB=buffer.create(ab)
buffer.copy(aB,0,ap,aq*ab,ab)

local aC=buffer.create(ac)
buffer.copy(aC,0,aB,0,ab)
buffer.copy(aC,ab,az,0,ab)

az=Compress(ak,aC,0,aa,al+ah)
aA=aA/2
end

buffer.copy(ap,aq*ab,az,0,ab)
aq=aq+1
buffer.copy(ar,0,ak,0,ab)
av=af

as+=1
at=0
au=0
end
end

local ax=ao==0 and 0 or((ao-1)%aa+1)
local ay=buffer.create(aa)

if ax>0 then
buffer.copy(ay,0,am,ao-ax,ax)
end

local az:buffer
local aA:buffer
local aB:number
local aC:number

if as>0 then
local aD=al+av+ag
local aE=Compress(ar,ay,as,ax,aD)

for aF=aq,2,-1 do
local aG=buffer.create(ab)
buffer.copy(aG,0,ap,(aF-1)*ab,ab)

local aH=buffer.create(ac)
buffer.copy(aH,0,aG,0,ab)
buffer.copy(aH,ab,aE,0,ab)

aE=Compress(ak,aH,0,aa,al+ah)
end

az=ak
local aF=buffer.create(ab)
buffer.copy(aF,0,ap,0,ab)

aA=buffer.create(ac)
buffer.copy(aA,0,aF,0,ab)
buffer.copy(aA,ab,aE,0,ab)

aB=aa
aC=al+ai+ah
else
az=ar
aA=ay
aB=ax
aC=al+av+ag+ai
end

local aD=buffer.create(an)
local aE=0

for aF=0,an//aa do
local aG=Compress(az,aA,aF,aB,aC,true)

local aH=math.min(aa,an-aE)
buffer.copy(aD,aE,aG,0,aH)
aE+=aH

if aE>=an then
break
end
end

return aD
end

return function(ak:buffer,al:number?):buffer
return ProcessMessage(aj,0,ak,al or 32)
end end function a.ae():typeof(__modImpl())local aa=a.cache.ae if not aa then aa={c=__modImpl()}a.cache.ae=aa end return aa.c end end do local function __modImpl()


























local aa=a.ac()
local ab=a.ad()
local ac=a.ae()


































local ad=64
local ae=32
local af=12

local ag:CSPRNGModule__DARKLUA_TYPE_i={
BlockExpansion=true,
SizeTarget=2048,
RekeyAfter=1024,

Key=buffer.create(0),
Nonce=buffer.create(0),
Buffer=buffer.create(0),

Counter=0,
BufferPosition=0,
BufferSize=0,
BytesLeft=0,

EntropyProviders={}
}::CSPRNGModule__DARKLUA_TYPE_i

local ah=buffer.create(ad)
local ai=math.max(math.floor(ag.RekeyAfter),2)
local aj=math.clamp(math.floor(ag.SizeTarget),64,4294967295)

local function Reset()
ag.Key=buffer.create(0)
ag.Nonce=buffer.create(0)
ag.Buffer=buffer.create(0)

ag.Counter=0
ag.BufferPosition=0
ag.BufferSize=0
end

local function GatherEntropy(ak:buffer?):number
local al=buffer.create(1024)
local am=0

local function WriteToBuffer(an:buffer)
local ao=buffer.len(an)
buffer.copy(al,am,an,0,ao)
am+=ao
end

local an=1.234
if tick then
an=tick()
local ao=buffer.create(8)
buffer.writef64(ao,0,an)
WriteToBuffer(ao)
end

local ao=os.clock()
local ap=buffer.create(8)
buffer.writef64(ap,0,ao)
WriteToBuffer(ap)

local aq=os.time()
local ar=buffer.create(8)
buffer.writeu32(ar,0,aq%0x100000000)
buffer.writeu32(ar,4,math.floor(aq/0x100000000))
WriteToBuffer(ar)

local as=5.678
if DateTime then
as=DateTime.now().UnixTimestampMillis
local at=buffer.create(8)
buffer.writef64(at,0,as)
WriteToBuffer(at)

local au=buffer.create(16)
buffer.writef32(au,0,as/1000)
buffer.writef32(au,4,(as%1000)/100)
buffer.writef32(au,8,as/86400000)
buffer.writef32(au,12,(as*0.001)%1)
WriteToBuffer(au)
else
WriteToBuffer(buffer.create(24))
end

local at=buffer.create(16)
buffer.writef32(at,0,ao/100)
buffer.writef32(at,4,an/1000)
buffer.writef32(at,8,(ao*12345.6789)%1)
buffer.writef32(at,12,(an*98765.4321)%1)
WriteToBuffer(at)

local au=buffer.create(32)
for av=0,7 do
local aw=math.noise(ao+av,aq+av,ao+aq+av)
local ax=math.noise(an+av*0.1,as*0.0001+av,ao*1.5+av)
local ay=math.noise(aq*0.01+av,ao+as*0.001,an+av*2)
local az=math.noise(as*0.00001+av,aq+ao+av,an*0.1+av)

buffer.writef32(au,av*4,aw+ax+ay+az)
end
WriteToBuffer(au)

local av=buffer.create(32)
for aw=0,7 do
local ax=os.clock()
local ay=0

local az=50+(aw*25)
for aA=1,az do
ay+=aA*aA+math.sin(aA/10)*math.cos(aA/7)
end

local aA=os.clock()
local aB=aA-ax
buffer.writef32(av,aw*4,aB*1000000)
end
WriteToBuffer(av)

local aw=buffer.create(24)
for ax=0,5 do
local ay=os.clock()

for az=1,20 do
buffer.create(64+az)
end

local az=os.clock()
buffer.writef32(aw,ax*4,(az-ay)*10000000)
end
WriteToBuffer(aw)

local ax=math.floor(an*1000000)
local ay=buffer.create(8)
buffer.writeu32(ay,0,ax%0x100000000)
buffer.writeu32(ay,4,math.floor(ax/0x100000000))
WriteToBuffer(ay)

if game then
if game.JobId and#game.JobId>0 then
local az=buffer.fromstring(game.JobId)
WriteToBuffer(az)
end

if game.PlaceId then
local az=buffer.create(8)
buffer.writeu32(az,0,game.PlaceId%0x100000000)
buffer.writeu32(az,4,math.floor(game.PlaceId/0x100000000))
WriteToBuffer(az)
end

if workspace and workspace.DistributedGameTime then
local az=buffer.create(8)
buffer.writef64(az,0,workspace.DistributedGameTime)
WriteToBuffer(az)

local aA=math.floor(workspace.DistributedGameTime*1000000)
local aB=buffer.create(8)
buffer.writeu32(aB,0,aA%0x100000000)
buffer.writeu32(aB,4,math.floor(aA/0x100000000))
WriteToBuffer(aB)
end
end

local az=buffer.create(128)
for aA=0,7 do
local aB={}
local aC=function()end
local aD=buffer.create(0)
local aE=newproxy()

local aF=string.gsub(tostring(aB),"table: ","")
local aG=string.gsub(tostring(aC),"function: ","")
local aH=string.gsub(tostring(aD),"buffer: ","")
local aI=string.gsub(tostring(aE),"userdata: ","")

local aJ=0
local aK=0
local aL=0
local aM=0
local aN=0

for aO=1,#aF do
aJ=bit32.bxor(aJ,string.byte(aF,aO))*31
end

if coroutine then
local aO=string.gsub(tostring(coroutine.create(function()end)),"thread: ","")
for aP=1,#aO do
aK=bit32.bxor(aK,string.byte(aO,aP))*31
end
end

for aO=1,#aG do
aL=bit32.bxor(aL,string.byte(aG,aO))*37
end
for aO=1,#aH do
aM=bit32.bxor(aM,string.byte(aH,aO))*41
end
for aO=1,#aI do
aN=bit32.bxor(aN,string.byte(aI,aO))*43
end

buffer.writeu32(az,aA*16,aJ)
buffer.writeu32(az,aA*16+4,aK)
buffer.writeu32(az,aA*16+8,aL)
buffer.writeu32(az,aA*16+12,bit32.bxor(aM,aN))
end
WriteToBuffer(az)

local function AddExtraEntropy(aA:buffer?,aB:boolean,aC:string?)
if not aA then
return
end

local aD=1024-am

if aD>0 then
local aE=buffer.len(aA)-aD
local aF=math.min(aD,buffer.len(aA))

if aE>0 and aB and aC then
warn(`CSPRNG: {aC} returned {aE} bytes more than available and was truncated to {aF} bytes`)
end

buffer.copy(al,am,aA,0,aF)
end
end

for aA,aB in ag.EntropyProviders do
local aC=1024-am
if aC>0 then
local aD:boolean,aE:buffer?=pcall(aB,aC)
if not aD then
warn(`CSPRNG Provider errored with {aE}`)
end

AddExtraEntropy(aE,true,`Entropy Provider #{aA}`)
end
end

if ak then
AddExtraEntropy(ak,false)
end

local aA=ac(al,ae+af)

ag.Key=buffer.create(ae)
buffer.copy(ag.Key,0,aA,0,ae)

ag.Nonce=buffer.create(af)
buffer.copy(ag.Nonce,0,aA,ae,af)

return buffer.len(al)-am
end

local function GenerateBlock()
buffer.fill(ah,0,0,ad)
local ak=ab(ah,ag.Key,ag.Nonce,ag.Counter,20)

ag.Buffer=if ag.BlockExpansion then ac(ak,aj)else ak
ag.BufferPosition=0
ag.BufferSize=buffer.len(ag.Buffer)
ag.Counter+=1

if ag.Counter%ai==0 then
GatherEntropy()
ag.Counter=0
end
end

local function GetBytes(ak:number):buffer
local al=buffer.create(ak)
local am=0

while am<ak do
if ag.BufferPosition>=ag.BufferSize then
GenerateBlock()
end

local an=ak-am
local ao=ag.BufferSize-ag.BufferPosition
local ap=math.min(an,ao)

buffer.copy(al,am,ag.Buffer,ag.BufferPosition,ap)
am+=ap
ag.BufferPosition+=ap
end

return al
end

local function GetFloat():number
if ag.BufferPosition+8>ag.BufferSize then
GenerateBlock()
end

local ak=buffer.readu32(ag.Buffer,ag.BufferPosition)
local al=buffer.readu32(ag.Buffer,ag.BufferPosition+4)
ag.BufferPosition+=8

local am=bit32.rshift(ak,5)
local an=bit32.rshift(al,6)

return(am*67108864.0+an)/9007199254740992.0
end

local function GetIntRange(ak:number,al:number):number
local am=al-ak+1
local an=0xFFFFFFFF
local ao=an-(an%am)

if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end

local ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4

if bit32.band(am,am-1)==0 then
return ak+bit32.band(ap,am-1)
else
while ap>ao do
if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end
ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4
end

return ak+(ap%am)
end
end

local function GetNumberRange(ak:number,al:number):number
if ak>al then
ak,al=al,ak
end

local am=al-ak
if am<=0 then
return ak
end

return ak+(GetFloat()*am)
end

local function GetRandomString(ak:number,al:boolean?):string|buffer
local am=buffer.create(ak)

for an=0,ak-1 do
buffer.writeu8(am,an,GetIntRange(36,122))
end

return if al
then am
else buffer.tostring(am)
end

local function GetEd25519RandomBytes():buffer
local ak=buffer.create(32)

for al=0,31 do
buffer.writeu8(ak,al,GetIntRange(0,255))
end

return ak
end

local function GetEd25519ClampedBytes(ak:buffer):buffer
local al=buffer.create(32)
buffer.copy(al,0,ak,0,32)

local am=buffer.readu8(al,0)
am=bit32.band(am,0xF8)
buffer.writeu8(al,0,am)

local an=buffer.readu8(al,31)
an=bit32.band(an,0x7F)
an=bit32.bor(an,0x40)
buffer.writeu8(al,31,an)

local ao=false
local ap=buffer.readu8(al,1)
for aq=2,30 do
if buffer.readu8(al,aq)~=ap then
ao=true
break
end
end

if not ao then
buffer.writeu8(al,15,bit32.bxor(ap,0x55))
end

return al
end

local function GetHexString(ak:number):string
local al=ak/2
local am=GetBytes(al)
local an=aa.ToHex(am)

return an
end

function ag.AddEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_h)
table.insert(ag.EntropyProviders,ak)
end

function ag.RemoveEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_h)
for al=#ag.EntropyProviders,1,-1 do
if ag.EntropyProviders[al]==ak then
table.remove(ag.EntropyProviders,al)
break
end
end
end

function ag.Random():number
return GetFloat()
end

function ag.RandomInt(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) can't be less than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=1
else
am=al
an=ak
end

return GetIntRange(an,am)
end

function ag.RandomNumber(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) must be bigger than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=0
else
am=al
an=ak
end

return GetNumberRange(an,am)
end

function ag.RandomBytes(ak:number):buffer
if type(ak)~="number"then
error(`Count must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Count must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Count must be an integer",2)
end

return GetBytes(ak)
end

function ag.RandomString(ak:number,al:boolean?):string|buffer
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if al~=nil and type(al)~="boolean"then
error(`AsBuffer must be a boolean or nil, got {typeof(al)}`,2)
end

return GetRandomString(ak,al)
end

function ag.RandomHex(ak:number):string
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if ak%2~=0 then
error(`Length must be even, got {ak}`,2)
end

return GetHexString(ak)
end

function ag.Ed25519ClampedBytes(ak:buffer):buffer
if type(ak)~="buffer"then
error(`Input must be a buffer, got {typeof(ak)}`,2)
end

return GetEd25519ClampedBytes(ak)
end

function ag.Ed25519Random():buffer
return GetEd25519ClampedBytes(GetEd25519RandomBytes())
end

function ag.Reseed(ak:buffer?)
if ak~=nil and type(ak)~="buffer"then
error(`CustomEntropy must be a buffer or nil, got {typeof(ak)}`,2)
end

Reset()
GatherEntropy(ak)
end

ag.BytesLeft=GatherEntropy()
GenerateBlock()

return ag end function a.af():typeof(__modImpl())local aa=a.cache.af if not aa then aa={c=__modImpl()}a.cache.af=aa end return aa.c end end do local function __modImpl()























local aa=a.U()
local ab=a.W()

local ac=a.Y()
local ad=a.X()

local ae=a.aa()
local af=a._()

local ag=a.ab()
local ah=a.af()

local ai=32
local aj=32

local ak=256
local al=8380417

local am={
CSPRNG=ah
}

local function CompareBufferSlices(an:buffer,ao:number,ap:buffer,aq:number,ar:number):boolean
local as=0

if ar==32 then
as=bit32.bor(
bit32.bxor(buffer.readu32(an,ao),buffer.readu32(ap,aq)),
bit32.bxor(buffer.readu32(an,ao+4),buffer.readu32(ap,aq+4)),
bit32.bxor(buffer.readu32(an,ao+8),buffer.readu32(ap,aq+8)),
bit32.bxor(buffer.readu32(an,ao+12),buffer.readu32(ap,aq+12)),
bit32.bxor(buffer.readu32(an,ao+16),buffer.readu32(ap,aq+16)),
bit32.bxor(buffer.readu32(an,ao+20),buffer.readu32(ap,aq+20)),
bit32.bxor(buffer.readu32(an,ao+24),buffer.readu32(ap,aq+24)),
bit32.bxor(buffer.readu32(an,ao+28),buffer.readu32(ap,aq+28))
)
return as==0
end

local at=bit32.band(ar,bit32.bnot(3))
for au=0,at-4,4 do
as=bit32.bor(as,bit32.bxor(buffer.readu32(an,ao+au),buffer.readu32(ap,aq+au)))
end

for au=at,ar-1 do
as=bit32.bor(as,bit32.bxor(buffer.readu8(an,ao+au),buffer.readu8(ap,aq+au)))
end

return as==0
end

local function Keygen(an:buffer,ao:buffer,ap:buffer,aq:number,ar:number,as:number,at:number)
if not af.CheckKeygenParams(aq,ar,as,at)then
error"Invalid keygen parameters"
end

local au=ag.BitWidth(al)-as
local av=ag.BitWidth(2*at)
local aw=ar*av*32
local ax=aq*av*32
local ay=bit32.lshift(1,as-1)

local az=32
local aA=0
local aB=aA+32
local aC=aB+32
local aD=aC+64
local aE=aD+aw
local aF=aE+ax

local aG=buffer.create(2)
buffer.writeu8(aG,0,aq)
buffer.writeu8(aG,1,ar)

local aH=buffer.create(34)
buffer.copy(aH,0,an,0,32)
buffer.copy(aH,32,aG,0,2)

local aI=aa.SHAKE256(aH,128)

local aJ=buffer.create(32)
local aK=buffer.create(64)
local aL=buffer.create(32)

buffer.copy(aJ,0,aI,0,32)
buffer.copy(aK,0,aI,32,64)
buffer.copy(aL,0,aI,96,32)

local aM=buffer.create(aq*ar*ak*4)
ae.ExpandA(aJ,aM,aq,ar)

local aN=buffer.create(ar*ak*4)
local aO=buffer.create(aq*ak*4)

ae.ExpandS(aK,aN,at,ar,0)
ae.ExpandS(aK,aO,at,aq,ar)

local aP=buffer.create(ar*ak*4)
ac.Copy(aN,aP,ar)
ac.ForwardNTT(aP,ar)

local aQ=buffer.create(aq*ak*4)
ac.MatrixMultiply(aM,aP,aQ,aq,ar,ar,1)
ac.InverseNTT(aQ,aq)
ac.AddTo(aO,aQ,aq)

local aR=buffer.create(aq*ak*4)
local aS=buffer.create(aq*ak*4)
ac.Power2Round(aQ,aR,aS,aq,as)

buffer.copy(ao,0,aJ,0,32)
local aT=buffer.create(buffer.len(ao)-az)
ac.Encode(aR,aT,aq,au)
buffer.copy(ao,az,aT,0,buffer.len(aT))

local aU=aa.SHAKE256(ao,64)

buffer.copy(ap,aA,aJ,0,32)
buffer.copy(ap,aB,aL,0,32)
buffer.copy(ap,aC,aU,0,64)

ac.SubFromX(aN,ar,at)
ac.SubFromX(aO,aq,at)

local aV=buffer.create(aw)
local b=buffer.create(ax)
ac.Encode(aN,aV,ar,av)
ac.Encode(aO,b,aq,av)

buffer.copy(ap,aD,aV,0,aw)
buffer.copy(ap,aE,b,0,ax)

ac.SubFromX(aS,aq,ay)

local c=buffer.create(buffer.len(ap)-aF)
ac.Encode(aS,c,aq,as)
buffer.copy(ap,aF,c,0,buffer.len(c))
end

local function SignMuCore(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number,aA:number):boolean
local aB=bit32.lshift(1,at-1)
local aC=ag.BitWidth(2*au)
local aD=as*aC*32
local aE=ar*aC*32
local aF=bit32.lshift(aw,1)
local aG=math.floor((al-1)/aF)
local aH=ag.BitWidth(aG-1)
local aI=math.floor((2*aA)/8)
local aJ=ag.BitWidth(av)

local aK=0
local aL=aK+32
local aM=aL+32
local aN=aM+64
local aO=aN+aD
local aP=aO+aE

local aQ=buffer.create(32)
local aR=buffer.create(32)

buffer.copy(aQ,0,ap,aK,32)
buffer.copy(aR,0,ap,aL,32)

local aS=buffer.create(ar*as*ak*4)
ae.ExpandA(aQ,aS,ar,as)

local aT=buffer.create(128)
buffer.copy(aT,0,aR,0,32)
buffer.copy(aT,32,ao,0,32)
buffer.copy(aT,64,an,0,64)

local aU=aa.SHAKE256(aT,64)

local aV=buffer.create(as*ak*4)
local b=buffer.create(ar*ak*4)
local c=buffer.create(ar*ak*4)

local d=buffer.create(aD)
local e=buffer.create(aE)
local f=buffer.create(buffer.len(ap)-aP)

buffer.copy(d,0,ap,aN,aD)
buffer.copy(e,0,ap,aO,aE)
buffer.copy(f,0,ap,aP,buffer.len(f))

ac.Decode(d,aV,as,aC)
ac.Decode(e,b,ar,aC)
ac.Decode(f,c,ar,at)

ac.SubFromX(aV,as,au)
ac.SubFromX(b,ar,au)
ac.SubFromX(c,ar,aB)

ac.ForwardNTT(aV,as)
ac.ForwardNTT(b,ar)
ac.ForwardNTT(c,ar)

local g=false
local h=0

local i=buffer.create(as*ak*4)
local j=buffer.create(as*ak*4)
local k=buffer.create(ar*ak*4)
local l=buffer.create(ar*ak*4)
local m=buffer.create(ak*4)
local n=buffer.create(as*ak*4)
local o=buffer.create(ar*ak*4)
local p=buffer.create(ar*ak*4)
local q=buffer.create(ar*ak*4)
local r=buffer.create(ar*ak*4)
local s=buffer.create(ar*ak*4)
local t=buffer.create(aI)
local u=buffer.create(ar*aH*32)

while not g do
ae.ExpandMask(aU,h,i,av,as)

ac.Copy(i,j,as)
ac.ForwardNTT(j,as)
ac.MatrixMultiply(aS,j,k,ar,as,as,1)
ac.InverseNTT(k,ar)

ac.HighBits(k,l,ar,aF)
ac.Encode(l,u,ar,aH)

local v=buffer.create(64+buffer.len(u))
buffer.copy(v,0,an,0,64)
buffer.copy(v,64,u,0,buffer.len(u))

local w=aa.SHAKE256(v,aI)
buffer.copy(t,0,w,0,aI)

ae.SampleInBall(t,m,ax,aA)
ab.ForwardNTT(m)

ac.MultiplyByPoly(m,aV,n,as)
ac.InverseNTT(n,as)
ac.AddTo(i,n,as)

ac.MultiplyByPoly(m,b,p,ar)
ac.InverseNTT(p,ar)
ac.Negate(p,ar)
ac.AddTo(k,p,ar)
ac.LowBits(p,o,ar,aF)

local x=ac.InfinityNorm(n,as)
local y=ac.InfinityNorm(o,ar)

if x>=(av-ay)or y>=(aw-ay)then
g=false
else
ac.MultiplyByPoly(m,c,q,ar)
ac.InverseNTT(q,ar)

ac.Copy(q,r,ar)
ac.Negate(q,ar)
ac.AddTo(r,p,ar)
ac.MakeHint(q,p,s,ar,aF)

local z=ac.InfinityNorm(r,ar)
local A=ac.Count1s(s,ar)

if z>=aw or A>az then
g=false
else
g=true
end
end

h+=as
end

local v=0
local w=v+aI
local x=w+(32*as*aJ)

buffer.copy(aq,v,t,0,aI)

ac.SubFromX(n,as,av)
local y=buffer.create(32*as*aJ)
ac.Encode(n,y,as,aJ)
buffer.copy(aq,w,y,0,buffer.len(y))

local z=buffer.create(buffer.len(aq)-x)
ad.EncodeHintBits(s,z,ar,az)
buffer.copy(aq,x,z,0,buffer.len(z))

return g
end

local function Sign(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:buffer,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number,aA:number,aB:number):boolean
if not af.CheckSigningParams(as,at,au,av,aw,ax,ay,az,aA,aB)then
error"Invalid signing parameters"
end

if buffer.len(aq)>255 then
return false
end

local aC=64

local aD=buffer.create(64)
buffer.copy(aD,0,ap,aC,64)

local aE=buffer.create(2)
buffer.writeu8(aE,0,0)
buffer.writeu8(aE,1,buffer.len(aq))

local aF=buffer.create(66+buffer.len(aq)+buffer.len(an))
local aG=0
buffer.copy(aF,aG,aD,0,64)
aG+=64
buffer.copy(aF,aG,aE,0,2)
aG+=2
buffer.copy(aF,aG,aq,0,buffer.len(aq))
aG+=buffer.len(aq)
buffer.copy(aF,aG,an,0,buffer.len(an))

local aH=aa.SHAKE256(aF,64)

return SignMuCore(aH,ao,ap,ar,as,at,au,av,aw,ax,ay,az,aA,aB)
end

local function SignInternal(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number,aA:number):boolean
if not af.CheckSigningParams(ar,as,at,au,av,aw,ax,ay,az,aA)then
error"Invalid signing parameters"
end

local aB=64

local aC=buffer.create(64)
buffer.copy(aC,0,ap,aB,64)

local aD=buffer.create(64+buffer.len(an))
buffer.copy(aD,0,aC,0,64)
buffer.copy(aD,64,an,0,buffer.len(an))

local aE=aa.SHAKE256(aD,64)

return SignMuCore(aE,ao,ap,aq,ar,as,at,au,av,aw,ax,ay,az,aA)
end

local function SignMu(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number,aA:number):boolean
if not af.CheckSigningParams(ar,as,at,au,av,aw,ax,ay,az,aA)then
error"Invalid signing parameters"
end

if buffer.len(an)~=64 then
error"Mu must be 64 bytes"
end

return SignMuCore(an,ao,ap,aq,ar,as,at,au,av,aw,ax,ay,az,aA)
end

local function Verify(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number):boolean
if not af.CheckVerifyParams(ar,as,at,au,av,aw,ax,ay,az)then
error"Invalid verify parameters"
end

if buffer.len(ap)>255 then
return false
end

local aA=ag.BitWidth(al)-at
local aB=ag.BitWidth(au)
local aC=math.floor((2*az)/8)

local aD=ag.PubKeyLen(ar,at)
if buffer.len(ao)~=aD then
return false
end

local aE=ag.SigLen(ar,as,au,ay,az)
if buffer.len(aq)~=aE then
return false
end

local aF=bit32.lshift(av,1)
local aG=math.floor((al-1)/aF)
local aH=ag.BitWidth(aG-1)

local aI=32

local aJ=0
local aK=aJ+aC
local aL=aK+(32*as*aB)

local aM=false

local aN=buffer.create(32)
buffer.copy(aN,0,ao,0,32)

local aO=buffer.create(buffer.len(ao)-aI)
buffer.copy(aO,0,ao,aI,buffer.len(aO))

local aP=buffer.create(ar*ak*4)
ac.Decode(aO,aP,ar,aA)

local aQ=buffer.create(aC)
buffer.copy(aQ,0,aq,aJ,aC)

local aR=buffer.create(32*as*aB)
buffer.copy(aR,0,aq,aK,buffer.len(aR))

local aS=buffer.create(as*ak*4)
ac.Decode(aR,aS,as,aB)
ac.SubFromX(aS,as,au)

local aT=ac.InfinityNorm(aS,as)
aM=aM or(aT>=(au-ax))

local aU=buffer.create(buffer.len(aq)-aL)
buffer.copy(aU,0,aq,aL,buffer.len(aU))

local aV=buffer.create(ar*ak*4)
local b=ad.DecodeHintBits(aU,aV,ar,ay)
aM=aM or b

local c=buffer.create(ar*as*ak*4)
ae.ExpandA(aN,c,ar,as)

local d=aa.SHAKE256(ao,64)

local e=buffer.create(2)
buffer.writeu8(e,0,0)
buffer.writeu8(e,1,buffer.len(ap))

local f=buffer.create(66+buffer.len(ap)+buffer.len(an))
local g=0
buffer.copy(f,g,d,0,64)
g+=64
buffer.copy(f,g,e,0,2)
g+=2
buffer.copy(f,g,ap,0,buffer.len(ap))
g+=buffer.len(ap)
buffer.copy(f,g,an,0,buffer.len(an))

local h=aa.SHAKE256(f,64)

local i=buffer.create(ak*4)
ae.SampleInBall(aQ,i,aw,az)
ab.ForwardNTT(i)

local j=buffer.create(ar*ak*4)
local k=buffer.create(ar*ak*4)
local l=buffer.create(ar*ak*4)

ac.ForwardNTT(aS,as)
ac.MatrixMultiply(c,aS,j,ar,as,as,1)

ac.LeftShift(aP,ar,at)
ac.ForwardNTT(aP,ar)
ac.MultiplyByPoly(i,aP,l,ar)
ac.Negate(l,ar)

ac.AddTo(j,l,ar)
ac.InverseNTT(l,ar)

ac.UseHint(aV,l,k,ar,aF)

local m=buffer.create(ar*aH*32)
ac.Encode(k,m,ar,aH)

local n=buffer.create(64+buffer.len(m))
buffer.copy(n,0,h,0,64)
buffer.copy(n,64,m,0,buffer.len(m))

local o=aa.SHAKE256(n,aC)

local p=CompareBufferSlices(aQ,0,o,0,aC)
aM=aM or(not p)

return not aM
end

am.ML_DSA_44={
D=13,
Tau=39,
Gamma1=bit32.lshift(1,17),
Gamma2=math.floor((al-1)/88),
K=4,
L=4,
Eta=2,
Beta=78,
Omega=80,
Lambda=128,

KeygenSeedByteLen=ai,
PubKeyByteLen=ag.PubKeyLen(4,13),
SecKeyByteLen=ag.SecKeyLen(4,4,2,13),
SigningSeedByteLen=aj,
SigByteLen=ag.SigLen(4,4,131072,80,128),

KeyGen=function(an:buffer,ao:buffer,ap:buffer)
Keygen(an,ao,ap,4,4,13,2)
end,

Sign=function(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:buffer):boolean
return Sign(an,ao,ap,aq,ar,4,4,13,2,131072,95232,39,78,80,128)
end,

SignInternal=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return SignInternal(an,ao,ap,aq,4,4,13,2,131072,95232,39,78,80,128)
end,

SignMu=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return SignMu(an,ao,ap,aq,4,4,13,2,131072,95232,39,78,80,128)
end,

Verify=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return Verify(an,ao,ap,aq,4,4,13,131072,95232,39,78,80,128)
end,

GenerateKeys=function():(buffer,buffer)
local an=ah.RandomBytes(32)
local ao=buffer.create(1312)
local ap=buffer.create(2560)
am.ML_DSA_44.KeyGen(an,ao,ap)
return ao,ap
end
}

am.ML_DSA_65={
D=13,
Tau=49,
Gamma1=bit32.lshift(1,19),
Gamma2=math.floor((al-1)/32),
K=6,
L=5,
Eta=4,
Beta=196,
Omega=55,
Lambda=192,

KeygenSeedByteLen=ai,
PubKeyByteLen=ag.PubKeyLen(6,13),
SecKeyByteLen=ag.SecKeyLen(6,5,4,13),
SigningSeedByteLen=aj,
SigByteLen=ag.SigLen(6,5,524288,55,192),

KeyGen=function(an:buffer,ao:buffer,ap:buffer)
Keygen(an,ao,ap,6,5,13,4)
end,

Sign=function(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:buffer):boolean
return Sign(an,ao,ap,aq,ar,6,5,13,4,524288,261888,49,196,55,192)
end,

SignInternal=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return SignInternal(an,ao,ap,aq,6,5,13,4,524288,261888,49,196,55,192)
end,

SignMu=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return SignMu(an,ao,ap,aq,6,5,13,4,524288,261888,49,196,55,192)
end,

Verify=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return Verify(an,ao,ap,aq,6,5,13,524288,261888,49,196,55,192)
end,

GenerateKeys=function():(buffer,buffer)
local an=ah.RandomBytes(32)
local ao=buffer.create(1952)
local ap=buffer.create(4032)
am.ML_DSA_65.KeyGen(an,ao,ap)
return ao,ap
end
}

am.ML_DSA_87={
D=13,
Tau=60,
Gamma1=bit32.lshift(1,19),
Gamma2=math.floor((al-1)/32),
K=8,
L=7,
Eta=2,
Beta=120,
Omega=75,
Lambda=256,

KeygenSeedByteLen=ai,
PubKeyByteLen=ag.PubKeyLen(8,13),
SecKeyByteLen=ag.SecKeyLen(8,7,2,13),
SigningSeedByteLen=aj,
SigByteLen=ag.SigLen(8,7,524288,75,256),

KeyGen=function(an:buffer,ao:buffer,ap:buffer)
Keygen(an,ao,ap,8,7,13,2)
end,

Sign=function(an:buffer,ao:buffer,ap:buffer,aq:buffer,ar:buffer):boolean
return Sign(an,ao,ap,aq,ar,8,7,13,2,524288,261888,60,120,75,256)
end,

SignInternal=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return SignInternal(an,ao,ap,aq,8,7,13,2,524288,261888,60,120,75,256)
end,

SignMu=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return SignMu(an,ao,ap,aq,8,7,13,2,524288,261888,60,120,75,256)
end,

Verify=function(an:buffer,ao:buffer,ap:buffer,aq:buffer):boolean
return Verify(an,ao,ap,aq,8,7,13,524288,261888,60,120,75,256)
end,

GenerateKeys=function():(buffer,buffer)
local an=ah.RandomBytes(32)
local ao=buffer.create(2592)
local ap=buffer.create(4896)
am.ML_DSA_87.KeyGen(an,ao,ap)
return ao,ap
end
}

am.PubKeyLen=ag.PubKeyLen
am.SecKeyLen=ag.SecKeyLen
am.SigLen=ag.SigLen

return am end function a.ag():typeof(__modImpl())local aa=a.cache.ag if not aa then aa={c=__modImpl()}a.cache.ag=aa end return aa.c end end do local function __modImpl()























local aa=3329

local ab={}

function ab.Add(ac:number,ad:number):number
local ae=ac+ad
return if ae>=aa then ae-aa else ae
end

function ab.Subtract(ac:number,ad:number):number
local ae=ac-ad
return if ae<0 then ae+aa else ae
end

function ab.Multiply(ac:number,ad:number):number
return(ac*ad)%aa
end

function ab.Negate(ac:number):number
return if ac==0 then 0 else aa-ac
end

function ab.Power(ac:number,ad:number):number
local ae=if bit32.band(ad,1)==1 then ac else 1
local af=ac

local ag=ad
while ag>1 do
ag=bit32.rshift(ag,1)
af=ab.Multiply(af,af)

if bit32.band(ag,1)==1 then
ae=ab.Multiply(ae,af)
end
end

return ae
end

function ab.Invert(ac:number):number
if ac==0 then
return 0
end

return ab.Power(ac,aa-2)
end

function ab.BufferReduce(ac:buffer,ad:number)
local ae=aa
for af=0,ad-1 do
local ag=buffer.readu16(ac,af*2)
buffer.writeu16(ac,af*2,(ag%ae))
end
end

return ab end function a.ah():typeof(__modImpl())local aa=a.cache.ah if not aa then aa={c=__modImpl()}a.cache.ah=aa end return aa.c end end do local function __modImpl()


















local aa={}

function aa.CheckD(ab:number):boolean
return ab<12
end

function aa.CheckEta(ab:number):boolean
return(ab==2)or(ab==3)
end

function aa.CheckK(ab:number):boolean
return(ab==2)or(ab==3)or(ab==4)
end

function aa.CheckL(ab:number):boolean
return(ab==1)or(ab==4)or(ab==5)or(ab==10)or(ab==11)or(ab==12)
end



function aa.CheckKeygenParams(ab:number,ac:number):boolean
local ad=(ab==2)and(ac==3)
local ae=(ab==3)and(ac==2)
local af=(ab==4)and(ac==2)

return ad or ae or af
end

function aa.CheckEncryptParams(ab:number,ac:number,ad:number,ae:number,af:number):boolean
local ag=(ab==2)and(ac==3)and(ad==2)and(ae==10)and(af==4)
local ah=(ab==3)and(ac==2)and(ad==2)and(ae==10)and(af==4)
local ai=(ab==4)and(ac==2)and(ad==2)and(ae==11)and(af==5)

return ag or ah or ai
end

function aa.CheckDecryptParams(ab:number,ac:number,ad:number):boolean
local ae=(ab==2)and(ac==10)and(ad==4)
local af=(ab==3)and(ac==10)and(ad==4)
local ag=(ab==4)and(ac==11)and(ad==5)

return ae or af or ag
end

function aa.CheckEncapParams(ab:number,ac:number,ad:number,ae:number,af:number):boolean
return aa.CheckEncryptParams(ab,ac,ad,ae,af)
end

function aa.CheckDecapParams(ab:number,ac:number,ad:number,ae:number,af:number):boolean
return aa.CheckEncapParams(ab,ac,ad,ae,af)
end

return aa end function a.ai():typeof(__modImpl())local aa=a.cache.ai if not aa then aa={c=__modImpl()}a.cache.ai=aa end return aa.c end end do local function __modImpl()



















local aa=a.ai()

local ab={}

function ab.CtMemcmp(ac:buffer,ad:buffer):number
local ae=buffer.len(ac)
local af=buffer.len(ad)

if ae~=af then
return 0x00000000
end

local ag=0
local ah=ae-(ae%4)

for ai=0,ah-4,4 do
local aj=buffer.readu32(ac,ai)
local ak=buffer.readu32(ad,ai)
ag=bit32.bor(ag,bit32.bxor(aj,ak))
end

for ai=ah,ae-1 do
local aj=buffer.readu8(ac,ai)
local ak=buffer.readu8(ad,ai)
ag=bit32.bor(ag,bit32.bxor(aj,ak))
end

return if ag==0 then 0xFFFFFFFF else 0x00000000
end

function ab.CtCondMemcpy(ac:number,ad:buffer,ae:buffer,af:buffer)
local ag=buffer.len(ad)
local ah=bit32.band(ac,0xFFFFFFFF)
local ai=bit32.bnot(ah)
local aj=ag-(ag%4)

for ak=0,aj-4,4 do
local al=buffer.readu32(ae,ak)
local am=buffer.readu32(af,ak)
local an=bit32.bor(bit32.band(al,ah),bit32.band(am,ai))
buffer.writeu32(ad,ak,an)
end

for ak=aj,ag-1 do
local al=buffer.readu8(ae,ak)
local am=buffer.readu8(af,ak)
local an=bit32.bor(bit32.band(al,ah),bit32.band(am,ai))
buffer.writeu8(ad,ak,an)
end
end

function ab.BitReverse(ac:number,ad:number):number
local ae=0
for af=0,ad-1 do
local ag=bit32.band(bit32.rshift(ac,af),1)
ae=bit32.bor(ae,bit32.lshift(ag,ad-1-af))
end

return ae
end

function ab.GetPkePublicKeyLen(ac:number):number
if not aa.CheckK(ac)then
error"Invalid K parameter"
end

return ac*12*32+32
end

function ab.GetPkeSecretKeyLen(ac:number):number
if not aa.CheckK(ac)then
error"Invalid K parameter"
end

return ac*12*32
end

function ab.GetPkeCipherTextLen(ac:number,ad:number,ae:number):number
if not aa.CheckK(ac)then
error"Invalid K parameter"
end
if not aa.CheckD(ad)then
error"Invalid Du parameter"
end
if not aa.CheckD(ae)then
error"Invalid Dv parameter"
end

return 32*(ac*ad+ae)
end

function ab.GetKemPublicKeyLen(ac:number):number
return ab.GetPkePublicKeyLen(ac)
end

function ab.GetKemSecretKeyLen(ac:number):number
if not aa.CheckK(ac)then
error"Invalid K parameter"
end

return ab.GetPkeSecretKeyLen(ac)+ab.GetPkePublicKeyLen(ac)+32+32
end

function ab.GetKemCipherTextLen(ac:number,ad:number,ae:number):number
return ab.GetPkeCipherTextLen(ac,ad,ae)
end

return ab end function a.aj():typeof(__modImpl())local aa=a.cache.aj if not aa then aa={c=__modImpl()}a.cache.aj=aa end return aa.c end end do local function __modImpl()


















local aa=a.ah()
local ab=a.aj()

local ac=8
local ad=2^ac

local ae=3329
local af=17
local ag=aa.Invert(ad/2)

local ah={}

local ai=buffer.create((ad/2)*2)do
for aj=0,ad/2-1 do
local ak=ab.BitReverse(aj,ac-1)
local al=aa.Power(af,ak)
buffer.writeu16(ai,aj*2,al)
end
end

local aj=buffer.create((ad/2)*2)do
for ak=0,ad/2-1 do
local al=buffer.readu16(ai,ak*2)
local am=if al==0 then 0 else ae-al
buffer.writeu16(aj,ak*2,am)
end
end

local ak=buffer.create((ad/2)*2)do
for al=0,ad/2-1 do
local am=ab.BitReverse(al,ac-1)
local an=bit32.bxor(bit32.lshift(am,1),1)
local ao=aa.Power(af,an)
buffer.writeu16(ak,al*2,ao)
end
end

local al=table.create(ac)::{{number}}
for am=0,ac-1 do
al[am]={2^am,(2^am)*2}
end

function ah.Ntt(am:buffer)
local an=ai
local ao=al
local ap=ae

for aq=ac-1,1,-1 do
local ar=ao[aq][1]
local as=ao[aq][2]
local at=bit32.rshift(ad,aq+1)

for au=0,ad-1,as do
local av=at+bit32.rshift(au,aq+1)
local aw=buffer.readu16(an,av*2)

for ax=au,au+ar-1 do
local ay=ax*2
local az=(ax+ar)*2

local aA=buffer.readu16(am,ay)
local aB=buffer.readu16(am,az)

local aC=(aw*aB)%ap

local aD=if aA>=aC then aA-aC else aA-aC+ap

local aE=aA+aC
local aF=if aE>=ap then aE-ap else aE

buffer.writeu16(am,az,aD)
buffer.writeu16(am,ay,aF)
end
end
end
end

function ah.Intt(am:buffer)
local an=aj
local ao=ag
local ap=al
local aq=ae

for ar=1,ac-1 do
local as=ap[ar][1]
local at=ap[ar][2]
local au=bit32.rshift(ad,ar)-1

for av=0,ad-1,at do
local aw=au-bit32.rshift(av,ar+1)
local ax=buffer.readu16(an,aw*2)

for ay=av,av+as-1 do
local az=ay*2
local aA=(ay+as)*2

local aB=buffer.readu16(am,az)
local aC=buffer.readu16(am,aA)

local aD=aB+aC

local aE=if aD>=aq then aD-aq else aD
local aF=if aB>=aC then aB-aC else aB-aC+aq

local aG=(aF*ax)%aq

buffer.writeu16(am,az,aE)
buffer.writeu16(am,aA,aG)
end
end
end

for ar=0,ad-1 do
local as=ar*2
local at=buffer.readu16(am,as)

local au=(at*ao)%ae
buffer.writeu16(am,as,au)
end
end

function ah.NttAt(am:buffer,an:number)
local ao=ai
local ap=al
local aq=ae

for ar=ac-1,1,-1 do
local as=ap[ar][1]
local at=ap[ar][2]
local au=bit32.rshift(ad,ar+1)

for av=0,ad-1,at do
local aw=au+bit32.rshift(av,ar+1)
local ax=buffer.readu16(ao,aw*2)

for ay=av,av+as-1 do
local az=an+ay*2
local aA=an+(ay+as)*2

local aB=buffer.readu16(am,az)
local aC=buffer.readu16(am,aA)

local aD=(ax*aC)%aq

local aE=if aB>=aD then aB-aD else aB-aD+aq
local aF=aB+aD
local aG=if aF>=aq then aF-aq else aF

buffer.writeu16(am,aA,aE)
buffer.writeu16(am,az,aG)
end
end
end
end

function ah.InttAt(am:buffer,an:number)
local ao=aj
local ap=ag
local aq=al
local ar=ae

for as=1,ac-1 do
local at=aq[as][1]
local au=aq[as][2]
local av=bit32.rshift(ad,as)-1

for aw=0,ad-1,au do
local ax=av-bit32.rshift(aw,as+1)
local ay=buffer.readu16(ao,ax*2)

for az=aw,aw+at-1 do
local aA=an+az*2
local aB=an+(az+at)*2

local aC=buffer.readu16(am,aA)
local aD=buffer.readu16(am,aB)

local aE=aC+aD
local aF=if aE>=ar then aE-ar else aE
local aG=if aC>=aD then aC-aD else aC-aD+ar

local aH=(aG*ay)%ar

buffer.writeu16(am,aA,aF)
buffer.writeu16(am,aB,aH)
end
end
end

for as=0,ad-1 do
local at=an+as*2
local au=buffer.readu16(am,at)
buffer.writeu16(am,at,(au*ap)%ar)
end
end

function ah.PolyAddAt(am:buffer,an:number,ao:buffer,ap:number,aq:buffer,ar:number)
local as=ae
for at=0,255 do
local au=at*2
local av=buffer.readu16(am,an+au)
local aw=buffer.readu16(ao,ap+au)
local ax=av+aw
buffer.writeu16(aq,ar+au,if ax>=as then ax-as else ax)
end
end

function ah.PolyMul(am:buffer,an:buffer,ao:buffer)
local ap=ak
local aq=ae

for ar=0,ad/2-1 do
local as=ar*4
local at=buffer.readu16(ap,ar*2)

local au=buffer.readu16(am,as)
local av=buffer.readu16(am,as+2)
local aw=buffer.readu16(an,as)
local ax=buffer.readu16(an,as+2)

local ay=(au*aw)%aq
local az=(av*ax)%aq
local aA=(az*at)%aq

local aB=ay+aA
local aC=if aB>=aq then aB-aq else aB

local aD=(au*ax)%aq
local aE=(av*aw)%aq

local aF=aD+aE
local aG=if aF>=aq then aF-aq else aF

buffer.writeu16(ao,as,aC)
buffer.writeu16(ao,as+2,aG)
end
end

function ah.PolyMulAt(am:buffer,an:number,ao:buffer,ap:number,aq:buffer,ar:number)
local as=ak
local at=ae

for au=0,127 do
local av=au*4
local aw=buffer.readu16(as,au*2)

local ax=buffer.readu16(am,an+av)
local ay=buffer.readu16(am,an+av+2)
local az=buffer.readu16(ao,ap+av)
local aA=buffer.readu16(ao,ap+av+2)

local aB=(ax*az)%at
local aC=(ay*aA)%at
local aD=(aC*aw)%at

local aE=aB+aD
local aF=if aE>=at then aE-at else aE

local aG=(ax*aA)%at
local aH=(ay*az)%at

local aI=aG+aH
local aJ=if aI>=at then aI-at else aI

buffer.writeu16(aq,ar+av,aF)
buffer.writeu16(aq,ar+av+2,aJ)
end
end

function ah.PolyAdd(am:buffer,an:buffer,ao:buffer)
local ap=ae
for aq=0,ad-1 do
local ar=aq*2
local as=buffer.readu16(am,ar)
local at=buffer.readu16(an,ar)

local au=as+at
local av=if au>=ap then au-ap else au
buffer.writeu16(ao,ar,av)
end
end

function ah.PolySub(am:buffer,an:buffer,ao:buffer)
local ap=ae
for aq=0,ad-1 do
local ar=aq*2
local as=buffer.readu16(am,ar)
local at=buffer.readu16(an,ar)

local au=as-at
local av=if au<0 then au+ap else au
buffer.writeu16(ao,ar,av)
end
end

return ah end function a.ak():typeof(__modImpl())local aa=a.cache.ak if not aa then aa={c=__modImpl()}a.cache.ak=aa end return aa.c end end do local function __modImpl()


















local aa=a.ai()

local ab=8
local ac=2^ab

local ad={}

function ad.Encode(ae:buffer,af:number):buffer
if not aa.CheckL(af)then
error"Invalid encoding parameter l"
end

local ag=32*af
local ah=buffer.create(ag)

if af==1 then
local ai=ac/8

for aj=0,ai-1 do
local ak=aj*8
local al=0

for am=0,7 do
local an=buffer.readu16(ae,(ak+am)*2)
local ao=bit32.band(an,1)
al=bit32.bor(al,bit32.lshift(ao,am))
end

buffer.writeu8(ah,aj,al)
end

elseif af==4 then
local ai=ac/2

for aj=0,ai-1 do
local ak=aj*2
local al=bit32.band(buffer.readu16(ae,ak*2),0xF)
local am=bit32.band(buffer.readu16(ae,(ak+1)*2),0xF)

local an=bit32.bor(al,bit32.lshift(am,4))
buffer.writeu8(ah,aj,an)
end

elseif af==5 then
local ai=ac/8

for aj=0,ai-1 do
local ak=aj*8
local al=aj*5

local am=buffer.readu16(ae,(ak+0)*2)
local an=buffer.readu16(ae,(ak+1)*2)
local ao=buffer.readu16(ae,(ak+2)*2)
local ap=buffer.readu16(ae,(ak+3)*2)
local aq=buffer.readu16(ae,(ak+4)*2)
local ar=buffer.readu16(ae,(ak+5)*2)
local as=buffer.readu16(ae,(ak+6)*2)
local at=buffer.readu16(ae,(ak+7)*2)

buffer.writeu8(ah,al+0,bit32.bor(bit32.band(am,0x1F),bit32.lshift(bit32.band(an,0x07),5)))
buffer.writeu8(ah,al+1,bit32.bor(bit32.rshift(an,3),bit32.lshift(bit32.band(ao,0x1F),2),bit32.lshift(bit32.band(ap,0x01),7)))
buffer.writeu8(ah,al+2,bit32.bor(bit32.rshift(ap,1),bit32.lshift(bit32.band(aq,0x0F),4)))
buffer.writeu8(ah,al+3,bit32.bor(bit32.rshift(aq,4),bit32.lshift(bit32.band(ar,0x1F),1),bit32.lshift(bit32.band(as,0x03),6)))
buffer.writeu8(ah,al+4,bit32.bor(bit32.rshift(as,2),bit32.lshift(bit32.band(at,0x1F),3)))
end

elseif af==10 then
local ai=ac/4

for aj=0,ai-1 do
local ak=aj*4
local al=aj*5

local am=buffer.readu16(ae,(ak+0)*2)
local an=buffer.readu16(ae,(ak+1)*2)
local ao=buffer.readu16(ae,(ak+2)*2)
local ap=buffer.readu16(ae,(ak+3)*2)

buffer.writeu8(ah,al+0,bit32.band(am,0xFF))
buffer.writeu8(ah,al+1,bit32.bor(bit32.rshift(am,8),bit32.lshift(bit32.band(an,0x3F),2)))
buffer.writeu8(ah,al+2,bit32.bor(bit32.rshift(an,6),bit32.lshift(bit32.band(ao,0x0F),4)))
buffer.writeu8(ah,al+3,bit32.bor(bit32.rshift(ao,4),bit32.lshift(bit32.band(ap,0x03),6)))
buffer.writeu8(ah,al+4,bit32.rshift(ap,2))
end

elseif af==11 then
local ai=ac/8

for aj=0,ai-1 do
local ak=aj*8
local al=aj*11

local am=buffer.readu16(ae,(ak+0)*2)
local an=buffer.readu16(ae,(ak+1)*2)
local ao=buffer.readu16(ae,(ak+2)*2)
local ap=buffer.readu16(ae,(ak+3)*2)
local aq=buffer.readu16(ae,(ak+4)*2)
local ar=buffer.readu16(ae,(ak+5)*2)
local as=buffer.readu16(ae,(ak+6)*2)
local at=buffer.readu16(ae,(ak+7)*2)

buffer.writeu8(ah,al+0,bit32.band(am,0xFF))
buffer.writeu8(ah,al+1,bit32.bor(bit32.rshift(am,8),bit32.lshift(bit32.band(an,0x1F),3)))
buffer.writeu8(ah,al+2,bit32.bor(bit32.rshift(an,5),bit32.lshift(bit32.band(ao,0x03),6)))
buffer.writeu8(ah,al+3,bit32.rshift(ao,2))
buffer.writeu8(ah,al+4,bit32.bor(bit32.rshift(ao,10),bit32.lshift(bit32.band(ap,0x7F),1)))
buffer.writeu8(ah,al+5,bit32.bor(bit32.rshift(ap,7),bit32.lshift(bit32.band(aq,0x0F),4)))
buffer.writeu8(ah,al+6,bit32.bor(bit32.rshift(aq,4),bit32.lshift(bit32.band(ar,0x01),7)))
buffer.writeu8(ah,al+7,bit32.rshift(ar,1))
buffer.writeu8(ah,al+8,bit32.bor(bit32.rshift(ar,9),bit32.lshift(bit32.band(as,0x3F),2)))
buffer.writeu8(ah,al+9,bit32.bor(bit32.rshift(as,6),bit32.lshift(bit32.band(at,0x07),5)))
buffer.writeu8(ah,al+10,bit32.rshift(at,3))
end
else
local ai=ac/2

for aj=0,ai-1 do
local ak=aj*2
local al=aj*3

local am=buffer.readu16(ae,(ak+0)*2)
local an=buffer.readu16(ae,(ak+1)*2)

buffer.writeu8(ah,al+0,bit32.band(am,0xFF))
buffer.writeu8(ah,al+1,bit32.bor(bit32.rshift(am,8),bit32.lshift(bit32.band(an,0x0F),4)))
buffer.writeu8(ah,al+2,bit32.rshift(an,4))
end
end

return ah
end

function ad.EncodeAt(ae:buffer,af:number,ag:buffer,ah:number,ai:number)
if ai==12 then
for aj=0,127 do
local ak=af+aj*4
local al=ah+aj*3

local am=buffer.readu16(ae,ak)
local an=buffer.readu16(ae,ak+2)

buffer.writeu8(ag,al,bit32.band(am,0xFF))
buffer.writeu8(ag,al+1,bit32.bor(bit32.rshift(am,8),bit32.lshift(bit32.band(an,0x0F),4)))
buffer.writeu8(ag,al+2,bit32.rshift(an,4))
end
end
end

function ad.Decode(ae:buffer,af:number):buffer
if not aa.CheckL(af)then
error"Invalid encoding parameter l"
end

local ag=buffer.create(ac*2)
if af==1 then
local ah=ac/8

for ai=0,ah-1 do
local aj=buffer.readu8(ae,ai)
local ak=ai*8

for al=0,7 do
local am=bit32.band(bit32.rshift(aj,al),1)
buffer.writeu16(ag,(ak+al)*2,am)
end
end

elseif af==4 then
local ah=ac/2

for ai=0,ah-1 do
local aj=buffer.readu8(ae,ai)
local ak=ai*2

buffer.writeu16(ag,(ak+0)*2,bit32.band(aj,0x0F))
buffer.writeu16(ag,(ak+1)*2,bit32.rshift(aj,4))
end

elseif af==5 then
local ah=ac/8

for ai=0,ah-1 do
local aj=ai*8
local ak=ai*5

local al=buffer.readu8(ae,ak+0)
local am=buffer.readu8(ae,ak+1)
local an=buffer.readu8(ae,ak+2)
local ao=buffer.readu8(ae,ak+3)
local ap=buffer.readu8(ae,ak+4)

local aq=bit32.band(al,0x1F)
local ar=bit32.bor(bit32.rshift(al,5),bit32.lshift(bit32.band(am,0x03),3))
local as=bit32.band(bit32.rshift(am,2),0x1F)
local at=bit32.bor(bit32.rshift(am,7),bit32.lshift(bit32.band(an,0x0F),1))
local au=bit32.bor(bit32.rshift(an,4),bit32.lshift(bit32.band(ao,0x01),4))
local av=bit32.band(bit32.rshift(ao,1),0x1F)
local aw=bit32.bor(bit32.rshift(ao,6),bit32.lshift(bit32.band(ap,0x07),2))
local ax=bit32.rshift(ap,3)

buffer.writeu16(ag,(aj+0)*2,aq)
buffer.writeu16(ag,(aj+1)*2,ar)
buffer.writeu16(ag,(aj+2)*2,as)
buffer.writeu16(ag,(aj+3)*2,at)
buffer.writeu16(ag,(aj+4)*2,au)
buffer.writeu16(ag,(aj+5)*2,av)
buffer.writeu16(ag,(aj+6)*2,aw)
buffer.writeu16(ag,(aj+7)*2,ax)
end

elseif af==10 then
local ah=ac/4

for ai=0,ah-1 do
local aj=ai*4
local ak=ai*5

local al=buffer.readu8(ae,ak+0)
local am=buffer.readu8(ae,ak+1)
local an=buffer.readu8(ae,ak+2)
local ao=buffer.readu8(ae,ak+3)
local ap=buffer.readu8(ae,ak+4)

local aq=bit32.bor(al,bit32.lshift(bit32.band(am,0x03),8))
local ar=bit32.bor(bit32.rshift(am,2),bit32.lshift(bit32.band(an,0x0F),6))
local as=bit32.bor(bit32.rshift(an,4),bit32.lshift(bit32.band(ao,0x3F),4))
local at=bit32.bor(bit32.rshift(ao,6),bit32.lshift(ap,2))

buffer.writeu16(ag,(aj+0)*2,aq)
buffer.writeu16(ag,(aj+1)*2,ar)
buffer.writeu16(ag,(aj+2)*2,as)
buffer.writeu16(ag,(aj+3)*2,at)
end

elseif af==11 then
local ah=ac/8

for ai=0,ah-1 do
local aj=ai*8
local ak=ai*11

local al=buffer.readu8(ae,ak+0)
local am=buffer.readu8(ae,ak+1)
local an=buffer.readu8(ae,ak+2)
local ao=buffer.readu8(ae,ak+3)
local ap=buffer.readu8(ae,ak+4)
local aq=buffer.readu8(ae,ak+5)
local ar=buffer.readu8(ae,ak+6)
local as=buffer.readu8(ae,ak+7)
local at=buffer.readu8(ae,ak+8)
local au=buffer.readu8(ae,ak+9)
local av=buffer.readu8(ae,ak+10)

local aw=bit32.bor(al,bit32.lshift(bit32.band(am,0x07),8))
local ax=bit32.bor(bit32.rshift(am,3),bit32.lshift(bit32.band(an,0x3F),5))
local ay=bit32.bor(bit32.rshift(an,6),bit32.lshift(ao,2),bit32.lshift(bit32.band(ap,0x01),10))
local az=bit32.bor(bit32.rshift(ap,1),bit32.lshift(bit32.band(aq,0x0F),7))
local aA=bit32.bor(bit32.rshift(aq,4),bit32.lshift(bit32.band(ar,0x7F),4))
local aB=bit32.bor(bit32.rshift(ar,7),bit32.lshift(as,1),bit32.lshift(bit32.band(at,0x03),9))
local aC=bit32.bor(bit32.rshift(at,2),bit32.lshift(bit32.band(au,0x1F),6))
local aD=bit32.bor(bit32.rshift(au,5),bit32.lshift(av,3))

buffer.writeu16(ag,(aj+0)*2,aw)
buffer.writeu16(ag,(aj+1)*2,ax)
buffer.writeu16(ag,(aj+2)*2,ay)
buffer.writeu16(ag,(aj+3)*2,az)
buffer.writeu16(ag,(aj+4)*2,aA)
buffer.writeu16(ag,(aj+5)*2,aB)
buffer.writeu16(ag,(aj+6)*2,aC)
buffer.writeu16(ag,(aj+7)*2,aD)
end
else
local ah=ac/2

for ai=0,ah-1 do
local aj=ai*2
local ak=ai*3

local al=buffer.readu8(ae,ak+0)
local am=buffer.readu8(ae,ak+1)
local an=buffer.readu8(ae,ak+2)

local ao=bit32.bor(al,bit32.lshift(bit32.band(am,0x0F),8))
local ap=bit32.bor(bit32.rshift(am,4),bit32.lshift(an,4))

if ao>=3329 or ap>=3329 then
error"Invalid polynomial coefficient encoding"
end

buffer.writeu16(ag,(aj+0)*2,ao)
buffer.writeu16(ag,(aj+1)*2,ap)
end
end

return ag
end

function ad.DecodeAt(ae:buffer,af:number,ag:buffer,ah:number,ai:number)
if ai==12 then
for aj=0,127 do
local ak=af+aj*3
local al=ah+aj*4

local am=buffer.readu8(ae,ak)
local an=buffer.readu8(ae,ak+1)
local ao=buffer.readu8(ae,ak+2)

local ap=bit32.bor(am,bit32.lshift(bit32.band(an,0x0F),8))
local aq=bit32.bor(bit32.rshift(an,4),bit32.lshift(ao,4))

if ap>=3329 or aq>=3329 then
error"Invalid polynomial coefficient encoding"
end

buffer.writeu16(ag,al,ap)
buffer.writeu16(ag,al+2,aq)
end
end
end

return ad end function a.al():typeof(__modImpl())local aa=a.cache.al if not aa then aa={c=__modImpl()}a.cache.al=aa end return aa.c end end do local function __modImpl()











local aa=a.ai()

local ab=256
local ac=3329

local ad={}

function ad.Compress(ae:number,af:number):number
local ag=ae*(2^af)
local ah=1664
local ai=ag+ah
local aj=ai//ac
local ak=(2^af)-1

return bit32.band(aj,ak)
end

function ad.Decompress(ae:number,af:number):number
local ag=ae*ac
local ah=bit32.rshift(ag,af)
local ai=bit32.band(bit32.rshift(ag,af-1),1)
return ah+ai
end

function ad.PolyCompress(ae:buffer,af:number)
if not aa.CheckD(af)then
error"Invalid compression parameter d"
end

local ag=ac

if af==1 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*2
local ak=aj+1664
local al=ak//ag
buffer.writeu16(ae,ah*2,bit32.band(al,1))
end
elseif af==4 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*16
local ak=aj+1664
local al=ak//ag
buffer.writeu16(ae,ah*2,bit32.band(al,15))
end
elseif af==5 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*32
local ak=aj+1664
local al=ak//ag
buffer.writeu16(ae,ah*2,bit32.band(al,31))
end
elseif af==10 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*1024
local ak=aj+1664
local al=ak//ag
buffer.writeu16(ae,ah*2,bit32.band(al,1023))
end
elseif af==11 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*2048
local ak=aj+1664
local al=ak//ag
buffer.writeu16(ae,ah*2,bit32.band(al,2047))
end
else
local ah=ad.Compress
for ai=0,ab-1 do
local aj=buffer.readu16(ae,ai*2)
local ak=ah(aj,af)
buffer.writeu16(ae,ai*2,ak)
end
end
end

function ad.PolyDecompress(ae:buffer,af:number)
if not aa.CheckD(af)then
error"Invalid decompression parameter d"
end

local ag=ac

if af==1 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*ag
local ak=bit32.rshift(aj,1)
local al=bit32.band(aj,1)
buffer.writeu16(ae,ah*2,ak+al)
end
elseif af==4 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*ag
local ak=bit32.rshift(aj,4)
local al=bit32.band(bit32.rshift(aj,3),1)
buffer.writeu16(ae,ah*2,ak+al)
end
elseif af==5 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*ag
local ak=bit32.rshift(aj,5)
local al=bit32.band(bit32.rshift(aj,4),1)
buffer.writeu16(ae,ah*2,ak+al)
end
elseif af==10 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*ag
local ak=bit32.rshift(aj,10)
local al=bit32.band(bit32.rshift(aj,9),1)
buffer.writeu16(ae,ah*2,ak+al)
end
elseif af==11 then
for ah=0,ab-1 do
local ai=buffer.readu16(ae,ah*2)
local aj=ai*ag
local ak=bit32.rshift(aj,11)
local al=bit32.band(bit32.rshift(aj,10),1)
buffer.writeu16(ae,ah*2,ak+al)
end
else
local ah=ad.Decompress
for ai=0,ab-1 do
local aj=buffer.readu16(ae,ai*2)
local ak=ah(aj,af)
buffer.writeu16(ae,ai*2,ak)
end
end
end

return ad end function a.am():typeof(__modImpl())local aa=a.cache.am if not aa then aa={c=__modImpl()}a.cache.am=aa end return aa.c end end do local function __modImpl()












local aa=a.ak()
local ab=a.ai()
local ac=a.al()
local ad=a.am()

local ae=8
local af=2^ae
local ag=3329
local ah=af*2

local ai=buffer.create(af*2)
local aj=buffer.create(af*2)
local ak=buffer.create(af*2)
local al=buffer.create(af*2)

local am={}

function am.VecCreate(an:number):buffer
return buffer.create(an*ah)
end

function am.MatCreate(an:number,ao:number):buffer
return buffer.create(an*ao*ah)
end

function am.MatSetPoly(an:buffer,ao:number,ap:number,aq:number,ar:buffer)
local as=ao*aq+ap
local at=as*ah

buffer.copy(an,at,ar,0,ah)
end

function am.MatVecMultiply(an:buffer,ao:buffer,ap:buffer,aq:number,ar:number,as:number)
local at=ah
local au=aj
local av=ai

local aw=aa.PolyMulAt
local ax=aa.PolyAddAt

for ay=0,aq-1 do
local az=ay*at
buffer.fill(au,0,0,at)

for aA=0,ar-1 do
local aB=(ay*ar+aA)*at
local aC=aA*at

aw(an,aB,ao,aC,av,0)
ax(au,0,av,0,au,0)
end

buffer.copy(ap,az,au,0,at)
end
end

function am.VecNtt(an:buffer,ao:number)
local ap=ah
local aq=aa.NttAt
for ar=0,ao-1 do
aq(an,ar*ap)
end
end

function am.VecIntt(an:buffer,ao:number)
local ap=ah
local aq=aa.InttAt

for ar=0,ao-1 do
aq(an,ar*ap)
end
end

function am.VecAddTo(an:buffer,ao:buffer,ap:number)
local aq=ag
local ar=ap*af*2

for as=0,ar-2,2 do
local at=buffer.readu16(an,as)
local au=buffer.readu16(ao,as)
local av=at+au
buffer.writeu16(ao,as,if av>=aq then av-aq else av)
end
end

function am.VecAdd(an:buffer,ao:buffer,ap:buffer,aq:number)
if not(ab.CheckK(aq)or aq==1)then
error"Invalid vector dimension K"
end

local ar=aq*af
local as=ag
for at=0,ar-1 do
local au=at*2
local av=buffer.readu16(an,au)
local aw=buffer.readu16(ao,au)
local ax=av+aw
local ay=if ax>=as then ax-as else ax
buffer.writeu16(ap,au,ay)
end
end

function am.VecEncode(an:buffer,ao:number,ap:number):buffer
local aq=ao*32*ap
local ar=buffer.create(aq)
local as=ah
local at=32*ap

local au=ac.EncodeAt
local av=ac.Encode

if ap==12 then
for aw=0,ao-1 do
au(an,aw*as,ar,aw*at,12)
end
else
local aw=ak
for ax=0,ao-1 do
buffer.copy(aw,0,an,ax*as,as)
local ay=av(aw,ap)
buffer.copy(ar,ax*at,ay,0,at)
end
end

return ar
end

function am.VecDecode(an:buffer,ao:number,ap:number):buffer
local aq=buffer.create(ao*ah)
local ar=ah
local as=32*ap

local at=ac.DecodeAt
local au=ac.Decode

if ap==12 then
for av=0,ao-1 do
at(an,av*as,aq,av*ar,12)
end
else
local av=buffer.create(as)
for aw=0,ao-1 do
buffer.copy(av,0,an,aw*as,as)
local ax=au(av,ap)
buffer.copy(aq,aw*ar,ax,0,ar)
end
end

return aq
end

function am.VecCompress(an:buffer,ao:number,ap:number)
local aq=al
local ar=ah

for as=0,ao-1 do
local at=as*ar
buffer.copy(aq,0,an,at,ar)
ad.PolyCompress(aq,ap)
buffer.copy(an,at,aq,0,ar)
end
end

function am.VecDecompress(an:buffer,ao:number,ap:number)
local aq=al
local ar=ah

for as=0,ao-1 do
local at=as*ar
buffer.copy(aq,0,an,at,ar)
ad.PolyDecompress(aq,ap)
buffer.copy(an,at,aq,0,ar)
end
end

return am end function a.an():typeof(__modImpl())local aa=a.cache.an if not aa then aa={c=__modImpl()}a.cache.an=aa end return aa.c end end do local function __modImpl()




local aa={}

local ab,ac=buffer.create(96),buffer.create(96)do
local ad=0
local ae=29
local function GetNextBit():number
local af=ae%2
ae=bit32.bxor((ae-af)//2,142*af)

return af
end

for af=0,23 do
local ag=0
local ah:number

for ai=1,6 do
ah=if ah then ah*ah*2 else 1
ag+=GetNextBit()*ah
end

local ai=GetNextBit()*ah
buffer.writeu32(ac,af*4,ai)
buffer.writeu32(ab,af*4,ag+ai*ad)
end
end

local ad=buffer.create(100)
local ae=buffer.create(100)

local function Keccak(af:buffer,ag:buffer,ah:buffer,ai:number,aj:number,ak:number):()
local al=ak//8
local am,an=ac,ab

for ao=ai,ai+aj-1,ak do
for ap=0,(al-1)*4,4 do
local aq=ao+ap*2

buffer.writeu32(af,ap,bit32.bxor(
buffer.readu32(af,ap),
buffer.readu32(ah,aq)
))

buffer.writeu32(ag,ap,bit32.bxor(
buffer.readu32(ag,ap),
buffer.readu32(ah,aq+4)
))
end

local ap,aq=buffer.readu32(af,0),buffer.readu32(ag,0)
local ar,as=buffer.readu32(af,4),buffer.readu32(ag,4)
local at,au=buffer.readu32(af,8),buffer.readu32(ag,8)

local av,aw=buffer.readu32(af,12),buffer.readu32(ag,12)
local ax,ay=buffer.readu32(af,16),buffer.readu32(ag,16)
local az,aA=buffer.readu32(af,20),buffer.readu32(ag,20)

local aB,aC=buffer.readu32(af,24),buffer.readu32(ag,24)
local aD,aE=buffer.readu32(af,28),buffer.readu32(ag,28)
local aF,aG=buffer.readu32(af,32),buffer.readu32(ag,32)

local aH,aI=buffer.readu32(af,36),buffer.readu32(ag,36)
local aJ,aK=buffer.readu32(af,40),buffer.readu32(ag,40)
local aL,aM=buffer.readu32(af,44),buffer.readu32(ag,44)

local aN,aO=buffer.readu32(af,48),buffer.readu32(ag,48)
local aP,aQ=buffer.readu32(af,52),buffer.readu32(ag,52)
local aR,aS=buffer.readu32(af,56),buffer.readu32(ag,56)

local aT,aU=buffer.readu32(af,60),buffer.readu32(ag,60)
local aV,b=buffer.readu32(af,64),buffer.readu32(ag,64)
local c,d=buffer.readu32(af,68),buffer.readu32(ag,68)

local e,f=buffer.readu32(af,72),buffer.readu32(ag,72)
local g,h=buffer.readu32(af,76),buffer.readu32(ag,76)
local i,j=buffer.readu32(af,80),buffer.readu32(ag,80)

local k,l=buffer.readu32(af,84),buffer.readu32(ag,84)
local m,n=buffer.readu32(af,88),buffer.readu32(ag,88)
local o,p=buffer.readu32(af,92),buffer.readu32(ag,92)

local q,r=buffer.readu32(af,96),buffer.readu32(ag,96)

for s=0,92,4 do
local t,u=bit32.bxor(ap,az,aJ,aT,i),bit32.bxor(aq,aA,aK,aU,j)
local v,w=bit32.bxor(ar,aB,aL,aV,k),bit32.bxor(as,aC,aM,b,l)
local x,y=bit32.bxor(at,aD,aN,c,m),bit32.bxor(au,aE,aO,d,n)
local z,A=bit32.bxor(av,aF,aP,e,o),bit32.bxor(aw,aG,aQ,f,p)
local B,C=bit32.bxor(ax,aH,aR,g,q),bit32.bxor(ay,aI,aS,h,r)

local D,E=bit32.bxor(t,x*2+y//2147483648),bit32.bxor(u,y*2+x//2147483648)
local F,G=bit32.bxor(D,ar),bit32.bxor(E,as)
local H,I=bit32.bxor(D,aB),bit32.bxor(E,aC)
local J,K=bit32.bxor(D,aL),bit32.bxor(E,aM)
local L,M=bit32.bxor(D,aV),bit32.bxor(E,b)
local N,O=bit32.bxor(D,k),bit32.bxor(E,l)

ar=H//1048576+(I*4096);as=I//1048576+(H*4096)
aB=L//524288+(M*8192);aC=M//524288+(L*8192)
aL=F*2+G//2147483648;aM=G*2+F//2147483648
aV=J*1024+K//4194304;b=K*1024+J//4194304
k=N*4+O//1073741824;l=O*4+N//1073741824

D=bit32.bxor(v,z*2+A//2147483648);E=bit32.bxor(w,A*2+z//2147483648)
F=bit32.bxor(D,at);G=bit32.bxor(E,au)
H=bit32.bxor(D,aD);I=bit32.bxor(E,aE)
J=bit32.bxor(D,aN);K=bit32.bxor(E,aO)
L=bit32.bxor(D,c);M=bit32.bxor(E,d)
N=bit32.bxor(D,m);O=bit32.bxor(E,n)

at=J//2097152+(K*2048);au=K//2097152+(J*2048)
aD=N//8+bit32.bor(O*536870912,0);aE=O//8+bit32.bor(N*536870912,0)
aN=H*64+I//67108864;aO=I*64+H//67108864
c=(L*32768)+M//131072;d=(M*32768)+L//131072
m=F//4+bit32.bor(G*1073741824,0);n=G//4+bit32.bor(F*1073741824,0)

D=bit32.bxor(x,B*2+C//2147483648);E=bit32.bxor(y,C*2+B//2147483648)
F=bit32.bxor(D,av);G=bit32.bxor(E,aw)
H=bit32.bxor(D,aF);I=bit32.bxor(E,aG)
J=bit32.bxor(D,aP);K=bit32.bxor(E,aQ)
L=bit32.bxor(D,e);M=bit32.bxor(E,f)
N=bit32.bxor(D,o);O=bit32.bxor(E,p)

av=bit32.bor(L*2097152,0)+M//2048;aw=bit32.bor(M*2097152,0)+L//2048
aF=bit32.bor(F*268435456,0)+G//16;aG=bit32.bor(G*268435456,0)+F//16
aP=bit32.bor(J*33554432,0)+K//128;aQ=bit32.bor(K*33554432,0)+J//128
e=N//256+bit32.bor(O*16777216,0);f=O//256+bit32.bor(N*16777216,0)
o=H//512+bit32.bor(I*8388608,0);p=I//512+bit32.bor(H*8388608,0)
D=bit32.bxor(z,t*2+u//2147483648);E=bit32.bxor(A,u*2+t//2147483648)

F=bit32.bxor(D,ax);G=bit32.bxor(E,ay)
H=bit32.bxor(D,aH);I=bit32.bxor(E,aI)
J=bit32.bxor(D,aR);K=bit32.bxor(E,aS)
L=bit32.bxor(D,g);M=bit32.bxor(E,h)
N=bit32.bxor(D,q);O=bit32.bxor(E,r)

ax=(N*16384)+O//262144;ay=(O*16384)+N//262144
aH=bit32.bor(H*1048576,0)+I//4096;aI=bit32.bor(I*1048576,0)+H//4096
aR=L*256+M//16777216;aS=M*256+L//16777216
g=bit32.bor(F*134217728,0)+G//32;h=bit32.bor(G*134217728,0)+F//32
q=J//33554432+K*128;r=K//33554432+J*128

D=bit32.bxor(B,v*2+w//2147483648);E=bit32.bxor(C,w*2+v//2147483648)
H=bit32.bxor(D,az);I=bit32.bxor(E,aA)
J=bit32.bxor(D,aJ);K=bit32.bxor(E,aK)
L=bit32.bxor(D,aT);M=bit32.bxor(E,aU)
N=bit32.bxor(D,i);O=bit32.bxor(E,j)
az=J*8+K//536870912;aA=K*8+J//536870912
aJ=(N*262144)+O//16384;aK=(O*262144)+N//16384
aT=H//268435456+I*16;aU=I//268435456+H*16
i=L//8388608+M*512;j=M//8388608+L*512
ap=bit32.bxor(D,ap);aq=bit32.bxor(E,aq)

ap,ar,at,av,ax=bit32.bxor(ap,bit32.band(-1-ar,at)),bit32.bxor(ar,bit32.band(-1-at,av)),bit32.bxor(at,bit32.band(-1-av,ax)),bit32.bxor(av,bit32.band(-1-ax,ap)),bit32.bxor(ax,bit32.band(-1-ap,ar))::number
aq,as,au,aw,ay=bit32.bxor(aq,bit32.band(-1-as,au)),bit32.bxor(as,bit32.band(-1-au,aw)),bit32.bxor(au,bit32.band(-1-aw,ay)),bit32.bxor(aw,bit32.band(-1-ay,aq)),bit32.bxor(ay,bit32.band(-1-aq,as))::number
az,aB,aD,aF,aH=bit32.bxor(aF,bit32.band(-1-aH,az)),bit32.bxor(aH,bit32.band(-1-az,aB)),bit32.bxor(az,bit32.band(-1-aB,aD)),bit32.bxor(aB,bit32.band(-1-aD,aF)),bit32.bxor(aD,bit32.band(-1-aF,aH))::number
aA,aC,aE,aG,aI=bit32.bxor(aG,bit32.band(-1-aI,aA)),bit32.bxor(aI,bit32.band(-1-aA,aC)),bit32.bxor(aA,bit32.band(-1-aC,aE)),bit32.bxor(aC,bit32.band(-1-aE,aG)),bit32.bxor(aE,bit32.band(-1-aG,aI))::number
aJ,aL,aN,aP,aR=bit32.bxor(aL,bit32.band(-1-aN,aP)),bit32.bxor(aN,bit32.band(-1-aP,aR)),bit32.bxor(aP,bit32.band(-1-aR,aJ)),bit32.bxor(aR,bit32.band(-1-aJ,aL)),bit32.bxor(aJ,bit32.band(-1-aL,aN))::number
aK,aM,aO,aQ,aS=bit32.bxor(aM,bit32.band(-1-aO,aQ)),bit32.bxor(aO,bit32.band(-1-aQ,aS)),bit32.bxor(aQ,bit32.band(-1-aS,aK)),bit32.bxor(aS,bit32.band(-1-aK,aM)),bit32.bxor(aK,bit32.band(-1-aM,aO))::number
aT,aV,c,e,g=bit32.bxor(g,bit32.band(-1-aT,aV)),bit32.bxor(aT,bit32.band(-1-aV,c)),bit32.bxor(aV,bit32.band(-1-c,e)),bit32.bxor(c,bit32.band(-1-e,g)),bit32.bxor(e,bit32.band(-1-g,aT))::number
aU,b,d,f,h=bit32.bxor(h,bit32.band(-1-aU,b)),bit32.bxor(aU,bit32.band(-1-b,d)),bit32.bxor(b,bit32.band(-1-d,f)),bit32.bxor(d,bit32.band(-1-f,h)),bit32.bxor(f,bit32.band(-1-h,aU))::number
i,k,m,o,q=bit32.bxor(m,bit32.band(-1-o,q)),bit32.bxor(o,bit32.band(-1-q,i)),bit32.bxor(q,bit32.band(-1-i,k)),bit32.bxor(i,bit32.band(-1-k,m)),bit32.bxor(k,bit32.band(-1-m,o))::number
j,l,n,p,r=bit32.bxor(n,bit32.band(-1-p,r)),bit32.bxor(p,bit32.band(-1-r,j)),bit32.bxor(r,bit32.band(-1-j,l)),bit32.bxor(j,bit32.band(-1-l,n)),bit32.bxor(l,bit32.band(-1-n,p))::number

ap=bit32.bxor(ap,buffer.readu32(an,s))
aq=bit32.bxor(aq,buffer.readu32(am,s))
end

buffer.writeu32(af,0,ap);buffer.writeu32(ag,0,aq)
buffer.writeu32(af,4,ar);buffer.writeu32(ag,4,as)
buffer.writeu32(af,8,at);buffer.writeu32(ag,8,au)
buffer.writeu32(af,12,av);buffer.writeu32(ag,12,aw)
buffer.writeu32(af,16,ax);buffer.writeu32(ag,16,ay)
buffer.writeu32(af,20,az);buffer.writeu32(ag,20,aA)
buffer.writeu32(af,24,aB);buffer.writeu32(ag,24,aC)
buffer.writeu32(af,28,aD);buffer.writeu32(ag,28,aE)
buffer.writeu32(af,32,aF);buffer.writeu32(ag,32,aG)
buffer.writeu32(af,36,aH);buffer.writeu32(ag,36,aI)
buffer.writeu32(af,40,aJ);buffer.writeu32(ag,40,aK)
buffer.writeu32(af,44,aL);buffer.writeu32(ag,44,aM)
buffer.writeu32(af,48,aN);buffer.writeu32(ag,48,aO)
buffer.writeu32(af,52,aP);buffer.writeu32(ag,52,aQ)
buffer.writeu32(af,56,aR);buffer.writeu32(ag,56,aS)
buffer.writeu32(af,60,aT);buffer.writeu32(ag,60,aU)
buffer.writeu32(af,64,aV);buffer.writeu32(ag,64,b)
buffer.writeu32(af,68,c);buffer.writeu32(ag,68,d)
buffer.writeu32(af,72,e);buffer.writeu32(ag,72,f)
buffer.writeu32(af,76,g);buffer.writeu32(ag,76,h)
buffer.writeu32(af,80,i);buffer.writeu32(ag,80,j)
buffer.writeu32(af,84,k);buffer.writeu32(ag,84,l)
buffer.writeu32(af,88,m);buffer.writeu32(ag,88,n)
buffer.writeu32(af,92,o);buffer.writeu32(ag,92,p)
buffer.writeu32(af,96,q);buffer.writeu32(ag,96,r)
end
end

local function ProcessSponge(af:buffer,ag:number,ah:number,ai:number):buffer
local aj=(1600-ag)//8
buffer.fill(ad,0,0,100)
buffer.fill(ae,0,0,100)

local ak=ad
local al=ae

local am:number=buffer.len(af)
local an:number=am+1

local ao=an%aj
if ao~=0 then
an+=(aj-ao)
end

local ap=buffer.create(an)

if am>0 then
buffer.copy(ap,0,af,0,am)
end

if an-am==1 then
buffer.writeu8(ap,am,bit32.bor(ai,0x80))
else
buffer.writeu8(ap,am,ai)
if an-am>2 then
buffer.fill(ap,am+1,0,an-am-2)
end
buffer.writeu8(ap,an-1,0x80)
end

Keccak(ak,al,ap,0,an,aj)

local aq=buffer.create(ah)
local ar=0

local as=buffer.create(aj)
while ar<ah do
local at=math.min(aj,ah-ar)

for au=0,at-1 do
local av=ar+au
if av<ah then
local aw=au//8
local ax=au%8
local ay=aw*4

local az
if ax<4 then
az=bit32.extract(buffer.readu32(ak,ay),ax*8,8)
else
az=bit32.extract(buffer.readu32(al,ay),(ax-4)*8,8)
end
buffer.writeu8(aq,av,az)
end
end

ar+=at

if ar<ah then
Keccak(ak,al,as,0,aj,aj)
end
end

return aq
end

function aa.SHA3_256(af:buffer):buffer
return ProcessSponge(af,512,32,0x06)
end

function aa.SHA3_512(af:buffer):buffer
return ProcessSponge(af,1024,64,0x06)
end

function aa.SHAKE256(af:buffer,ag:number):buffer
return ProcessSponge(af,512,ag,0x1F)
end

return aa end function a.ao():typeof(__modImpl())local aa=a.cache.ao if not aa then aa={c=__modImpl()}a.cache.ao=aa end return aa.c end end do local function __modImpl()



















local aa=168
local ab=136

local ac=buffer.create(100)
local ad=buffer.create(100)
local ae=0

local af=buffer.create(100)
local ag=buffer.create(100)
local ah=0

local ai=buffer.create(aa)
local aj=buffer.create(ab)

local ak=buffer.create(aa)
local al=buffer.create(ab)

local am=buffer.create(168)
local an=buffer.create(128)
local ao=buffer.create(192)

local ap,aq=buffer.create(96),buffer.create(96)do
local ar=0
local as=29
local function GetNextBit():number
local at=as%2
as=bit32.bxor((as-at)//2,142*at)
return at
end

for at=0,23 do
local au=0
local av:number

for aw=1,6 do
av=if av then av*av*2 else 1
au+=GetNextBit()*av
end

local aw=GetNextBit()*av
buffer.writeu32(aq,at*4,aw)
buffer.writeu32(ap,at*4,au+aw*ar)
end
end

local function Keccak(ar:buffer,as:buffer,at:buffer,au:number,av:number,aw:number):()
local ax=aw//8
local ay,az=aq,ap

for aA=au,au+av-1,aw do
for aB=0,(ax-1)*4,4 do
local aC=aA+aB*2

buffer.writeu32(ar,aB,bit32.bxor(
buffer.readu32(ar,aB),
buffer.readu32(at,aC)
))

buffer.writeu32(as,aB,bit32.bxor(
buffer.readu32(as,aB),
buffer.readu32(at,aC+4)
))
end

local aB,aC=buffer.readu32(ar,0),buffer.readu32(as,0)
local aD,aE=buffer.readu32(ar,4),buffer.readu32(as,4)
local aF,aG=buffer.readu32(ar,8),buffer.readu32(as,8)

local aH,aI=buffer.readu32(ar,12),buffer.readu32(as,12)
local aJ,aK=buffer.readu32(ar,16),buffer.readu32(as,16)
local aL,aM=buffer.readu32(ar,20),buffer.readu32(as,20)

local aN,aO=buffer.readu32(ar,24),buffer.readu32(as,24)
local aP,aQ=buffer.readu32(ar,28),buffer.readu32(as,28)
local aR,aS=buffer.readu32(ar,32),buffer.readu32(as,32)

local aT,aU=buffer.readu32(ar,36),buffer.readu32(as,36)
local aV,b=buffer.readu32(ar,40),buffer.readu32(as,40)
local c,d=buffer.readu32(ar,44),buffer.readu32(as,44)

local e,f=buffer.readu32(ar,48),buffer.readu32(as,48)
local g,h=buffer.readu32(ar,52),buffer.readu32(as,52)
local i,j=buffer.readu32(ar,56),buffer.readu32(as,56)

local k,l=buffer.readu32(ar,60),buffer.readu32(as,60)
local m,n=buffer.readu32(ar,64),buffer.readu32(as,64)
local o,p=buffer.readu32(ar,68),buffer.readu32(as,68)

local q,r=buffer.readu32(ar,72),buffer.readu32(as,72)
local s,t=buffer.readu32(ar,76),buffer.readu32(as,76)
local u,v=buffer.readu32(ar,80),buffer.readu32(as,80)

local w,x=buffer.readu32(ar,84),buffer.readu32(as,84)
local y,z=buffer.readu32(ar,88),buffer.readu32(as,88)
local A,B=buffer.readu32(ar,92),buffer.readu32(as,92)

local C,D=buffer.readu32(ar,96),buffer.readu32(as,96)

for E=0,92,4 do
local F,G=bit32.bxor(aB,aL,aV,k,u),bit32.bxor(aC,aM,b,l,v)
local H,I=bit32.bxor(aD,aN,c,m,w),bit32.bxor(aE,aO,d,n,x)
local J,K=bit32.bxor(aF,aP,e,o,y),bit32.bxor(aG,aQ,f,p,z)
local L,M=bit32.bxor(aH,aR,g,q,A),bit32.bxor(aI,aS,h,r,B)
local N,O=bit32.bxor(aJ,aT,i,s,C),bit32.bxor(aK,aU,j,t,D)

local P,Q=bit32.bxor(F,J*2+K//2147483648),bit32.bxor(G,K*2+J//2147483648)
local R,S=bit32.bxor(P,aD),bit32.bxor(Q,aE)
local T,U=bit32.bxor(P,aN),bit32.bxor(Q,aO)
local V,W=bit32.bxor(P,c),bit32.bxor(Q,d)
local X,Y=bit32.bxor(P,m),bit32.bxor(Q,n)
local Z,_=bit32.bxor(P,w),bit32.bxor(Q,x)

aD=T//1048576+(U*4096);aE=U//1048576+(T*4096)
aN=X//524288+(Y*8192);aO=Y//524288+(X*8192)
c=R*2+S//2147483648;d=S*2+R//2147483648
m=V*1024+W//4194304;n=W*1024+V//4194304
w=Z*4+_//1073741824;x=_*4+Z//1073741824

P=bit32.bxor(H,L*2+M//2147483648);Q=bit32.bxor(I,M*2+L//2147483648)
R=bit32.bxor(P,aF);S=bit32.bxor(Q,aG)
T=bit32.bxor(P,aP);U=bit32.bxor(Q,aQ)
V=bit32.bxor(P,e);W=bit32.bxor(Q,f)
X=bit32.bxor(P,o);Y=bit32.bxor(Q,p)
Z=bit32.bxor(P,y);_=bit32.bxor(Q,z)

aF=V//2097152+(W*2048);aG=W//2097152+(V*2048)
aP=Z//8+bit32.bor(_*536870912,0);aQ=_//8+bit32.bor(Z*536870912,0)
e=T*64+U//67108864;f=U*64+T//67108864
o=(X*32768)+Y//131072;p=(Y*32768)+X//131072
y=R//4+bit32.bor(S*1073741824,0);z=S//4+bit32.bor(R*1073741824,0)

P=bit32.bxor(J,N*2+O//2147483648);Q=bit32.bxor(K,O*2+N//2147483648)
R=bit32.bxor(P,aH);S=bit32.bxor(Q,aI)
T=bit32.bxor(P,aR);U=bit32.bxor(Q,aS)
V=bit32.bxor(P,g);W=bit32.bxor(Q,h)
X=bit32.bxor(P,q);Y=bit32.bxor(Q,r)
Z=bit32.bxor(P,A);_=bit32.bxor(Q,B)

aH=bit32.bor(X*2097152,0)+Y//2048;aI=bit32.bor(Y*2097152,0)+X//2048
aR=bit32.bor(R*268435456,0)+S//16;aS=bit32.bor(S*268435456,0)+R//16
g=bit32.bor(V*33554432,0)+W//128;h=bit32.bor(W*33554432,0)+V//128
q=Z//256+bit32.bor(_*16777216,0);r=_//256+bit32.bor(Z*16777216,0)
A=T//512+bit32.bor(U*8388608,0);B=U//512+bit32.bor(T*8388608,0)
P=bit32.bxor(L,F*2+G//2147483648);Q=bit32.bxor(M,G*2+F//2147483648)

R=bit32.bxor(P,aJ);S=bit32.bxor(Q,aK)
T=bit32.bxor(P,aT);U=bit32.bxor(Q,aU)
V=bit32.bxor(P,i);W=bit32.bxor(Q,j)
X=bit32.bxor(P,s);Y=bit32.bxor(Q,t)
Z=bit32.bxor(P,C);_=bit32.bxor(Q,D)

aJ=(Z*16384)+_//262144;aK=(_*16384)+Z//262144
aT=bit32.bor(T*1048576,0)+U//4096;aU=bit32.bor(U*1048576,0)+T//4096
i=X*256+Y//16777216;j=Y*256+X//16777216
s=bit32.bor(R*134217728,0)+S//32;t=bit32.bor(S*134217728,0)+R//32
C=V//33554432+W*128;D=W//33554432+V*128

P=bit32.bxor(N,H*2+I//2147483648);Q=bit32.bxor(O,I*2+H//2147483648)
T=bit32.bxor(P,aL);U=bit32.bxor(Q,aM)
V=bit32.bxor(P,aV);W=bit32.bxor(Q,b)
X=bit32.bxor(P,k);Y=bit32.bxor(Q,l)
Z=bit32.bxor(P,u);_=bit32.bxor(Q,v)
aL=V*8+W//536870912;aM=W*8+V//536870912
aV=(Z*262144)+_//16384;b=(_*262144)+Z//16384
k=T//268435456+U*16;l=U//268435456+T*16
u=X//8388608+Y*512;v=Y//8388608+X*512
aB=bit32.bxor(P,aB);aC=bit32.bxor(Q,aC)

aB,aD,aF,aH,aJ=bit32.bxor(aB,bit32.band(-1-aD,aF)),bit32.bxor(aD,bit32.band(-1-aF,aH)),bit32.bxor(aF,bit32.band(-1-aH,aJ)),bit32.bxor(aH,bit32.band(-1-aJ,aB)),bit32.bxor(aJ,bit32.band(-1-aB,aD))::number
aC,aE,aG,aI,aK=bit32.bxor(aC,bit32.band(-1-aE,aG)),bit32.bxor(aE,bit32.band(-1-aG,aI)),bit32.bxor(aG,bit32.band(-1-aI,aK)),bit32.bxor(aI,bit32.band(-1-aK,aC)),bit32.bxor(aK,bit32.band(-1-aC,aE))::number
aL,aN,aP,aR,aT=bit32.bxor(aR,bit32.band(-1-aT,aL)),bit32.bxor(aT,bit32.band(-1-aL,aN)),bit32.bxor(aL,bit32.band(-1-aN,aP)),bit32.bxor(aN,bit32.band(-1-aP,aR)),bit32.bxor(aP,bit32.band(-1-aR,aT))::number
aM,aO,aQ,aS,aU=bit32.bxor(aS,bit32.band(-1-aU,aM)),bit32.bxor(aU,bit32.band(-1-aM,aO)),bit32.bxor(aM,bit32.band(-1-aO,aQ)),bit32.bxor(aO,bit32.band(-1-aQ,aS)),bit32.bxor(aQ,bit32.band(-1-aS,aU))::number
aV,c,e,g,i=bit32.bxor(c,bit32.band(-1-e,g)),bit32.bxor(e,bit32.band(-1-g,i)),bit32.bxor(g,bit32.band(-1-i,aV)),bit32.bxor(i,bit32.band(-1-aV,c)),bit32.bxor(aV,bit32.band(-1-c,e))::number
b,d,f,h,j=bit32.bxor(d,bit32.band(-1-f,h)),bit32.bxor(f,bit32.band(-1-h,j)),bit32.bxor(h,bit32.band(-1-j,b)),bit32.bxor(j,bit32.band(-1-b,d)),bit32.bxor(b,bit32.band(-1-d,f))::number
k,m,o,q,s=bit32.bxor(s,bit32.band(-1-k,m)),bit32.bxor(k,bit32.band(-1-m,o)),bit32.bxor(m,bit32.band(-1-o,q)),bit32.bxor(o,bit32.band(-1-q,s)),bit32.bxor(q,bit32.band(-1-s,k))::number
l,n,p,r,t=bit32.bxor(t,bit32.band(-1-l,n)),bit32.bxor(l,bit32.band(-1-n,p)),bit32.bxor(n,bit32.band(-1-p,r)),bit32.bxor(p,bit32.band(-1-r,t)),bit32.bxor(r,bit32.band(-1-t,l))::number
u,w,y,A,C=bit32.bxor(y,bit32.band(-1-A,C)),bit32.bxor(A,bit32.band(-1-C,u)),bit32.bxor(C,bit32.band(-1-u,w)),bit32.bxor(u,bit32.band(-1-w,y)),bit32.bxor(w,bit32.band(-1-y,A))::number
v,x,z,B,D=bit32.bxor(z,bit32.band(-1-B,D)),bit32.bxor(B,bit32.band(-1-D,v)),bit32.bxor(D,bit32.band(-1-v,x)),bit32.bxor(v,bit32.band(-1-x,z)),bit32.bxor(x,bit32.band(-1-z,B))::number

aB=bit32.bxor(aB,buffer.readu32(az,E))
aC=bit32.bxor(aC,buffer.readu32(ay,E))
end

buffer.writeu32(ar,0,aB);buffer.writeu32(as,0,aC)
buffer.writeu32(ar,4,aD);buffer.writeu32(as,4,aE)
buffer.writeu32(ar,8,aF);buffer.writeu32(as,8,aG)
buffer.writeu32(ar,12,aH);buffer.writeu32(as,12,aI)
buffer.writeu32(ar,16,aJ);buffer.writeu32(as,16,aK)
buffer.writeu32(ar,20,aL);buffer.writeu32(as,20,aM)
buffer.writeu32(ar,24,aN);buffer.writeu32(as,24,aO)
buffer.writeu32(ar,28,aP);buffer.writeu32(as,28,aQ)
buffer.writeu32(ar,32,aR);buffer.writeu32(as,32,aS)
buffer.writeu32(ar,36,aT);buffer.writeu32(as,36,aU)
buffer.writeu32(ar,40,aV);buffer.writeu32(as,40,b)
buffer.writeu32(ar,44,c);buffer.writeu32(as,44,d)
buffer.writeu32(ar,48,e);buffer.writeu32(as,48,f)
buffer.writeu32(ar,52,g);buffer.writeu32(as,52,h)
buffer.writeu32(ar,56,i);buffer.writeu32(as,56,j)
buffer.writeu32(ar,60,k);buffer.writeu32(as,60,l)
buffer.writeu32(ar,64,m);buffer.writeu32(as,64,n)
buffer.writeu32(ar,68,o);buffer.writeu32(as,68,p)
buffer.writeu32(ar,72,q);buffer.writeu32(as,72,r)
buffer.writeu32(ar,76,s);buffer.writeu32(as,76,t)
buffer.writeu32(ar,80,u);buffer.writeu32(as,80,v)
buffer.writeu32(ar,84,w);buffer.writeu32(as,84,x)
buffer.writeu32(ar,88,y);buffer.writeu32(as,88,z)
buffer.writeu32(ar,92,A);buffer.writeu32(as,92,B)
buffer.writeu32(ar,96,C);buffer.writeu32(as,96,D)
end
end

local ar={}

function ar.Reset128()
buffer.fill(ac,0,0,100)
buffer.fill(ad,0,0,100)
ae=0
end

function ar.Reset256()
buffer.fill(af,0,0,100)
buffer.fill(ag,0,0,100)
ah=0
end

function ar.Absorb128(as:buffer)
local at=buffer.len(as)
local au=aa

local av=ak
buffer.fill(av,0,0,au)

if at>0 then
buffer.copy(av,0,as,0,at)
end

if au-at==1 then
buffer.writeu8(av,at,0x9F)
else
buffer.writeu8(av,at,0x1F)
buffer.writeu8(av,au-1,0x80)
end

Keccak(ac,ad,av,0,au,au)
end

function ar.Absorb256(as:buffer)
local at=buffer.len(as)
local au=ab

local av=al
buffer.fill(av,0,0,au)

if at>0 then
buffer.copy(av,0,as,0,at)
end

if au-at==1 then
buffer.writeu8(av,at,0x9F)
else
buffer.writeu8(av,at,0x1F)
buffer.writeu8(av,au-1,0x80)
end

Keccak(af,ag,av,0,au,au)
end

function ar.Squeeze128Into(as:buffer,at:number,au:number?)
local av=au or 0
local aw=aa
local ax=ac
local ay=ad
local az=ae
local aA=ai

local aB=0
while aB<at do
if az>=aw then
Keccak(ax,ay,aA,0,aw,aw)
az=0
end

local aC=aw-az
if aC>at-aB then
aC=at-aB
end

local aD=0
while aD<aC do
local aE=az+aD
local aF=bit32.rshift(aE,3)
local aG=bit32.band(aE,7)
local aH=bit32.lshift(aF,2)

if aG==0 and aD+8<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
buffer.writeu32(as,av+aB+aD+4,buffer.readu32(ay,aH))
aD+=8
elseif aG==0 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
aD+=4
elseif aG==4 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ay,aH))
aD+=4
else
local aI
if aG<4 then
aI=bit32.extract(buffer.readu32(ax,aH),bit32.lshift(aG,3),8)
else
aI=bit32.extract(buffer.readu32(ay,aH),bit32.lshift(aG-4,3),8)
end
buffer.writeu8(as,av+aB+aD,aI)
aD+=1
end
end

aB+=aC
az+=aC
end

ae=az
end

function ar.Squeeze128(as:number):buffer
local at=if as==168 then am else buffer.create(as)
ar.Squeeze128Into(at,as,0)
return at
end

function ar.Squeeze256Into(as:buffer,at:number,au:number?)
local av=au or 0
local aw=ab
local ax=af
local ay=ag
local az=ah
local aA=aj

local aB=0
while aB<at do
if az>=aw then
Keccak(ax,ay,aA,0,aw,aw)
az=0
end

local aC=aw-az
if aC>at-aB then
aC=at-aB
end

local aD=0
while aD<aC do
local aE=az+aD
local aF=bit32.rshift(aE,3)
local aG=bit32.band(aE,7)
local aH=bit32.lshift(aF,2)

if aG==0 and aD+8<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
buffer.writeu32(as,av+aB+aD+4,buffer.readu32(ay,aH))
aD+=8
elseif aG==0 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ax,aH))
aD+=4
elseif aG==4 and aD+4<=aC then
buffer.writeu32(as,av+aB+aD,buffer.readu32(ay,aH))
aD+=4
else
local aI
if aG<4 then
aI=bit32.extract(buffer.readu32(ax,aH),bit32.lshift(aG,3),8)
else
aI=bit32.extract(buffer.readu32(ay,aH),bit32.lshift(aG-4,3),8)
end
buffer.writeu8(as,av+aB+aD,aI)
aD+=1
end
end

aB+=aC
az+=aC
end

ah=az
end

function ar.Squeeze256(as:number):buffer
local at=if as==128 then an
elseif as==192 then ao
else buffer.create(as)
ar.Squeeze256Into(at,as,0)
return at
end

return ar end function a.ap():typeof(__modImpl())local aa=a.cache.ap if not aa then aa={c=__modImpl()}a.cache.ap=aa end return aa.c end end do local function __modImpl()























local aa=a.an()
local ab=a.ai()
local ac=a.ao()
local ad=a.ap()

local ae=8
local af=2^ae
local ag=af*2

local ah=3329

local ai=buffer.create(168)
local aj=buffer.create(af*2)
local ak=buffer.create(192)
local al=buffer.create(33)

local function SamplePolyCbd2(am:buffer,an:buffer,ao:number?)
local ap=ao or 0
local aq=0x03
local ar=ah

for as=0,127 do
local at=as*2
local au=buffer.readu8(am,as)

local av=bit32.band(au,0x55)
local aw=bit32.band(bit32.rshift(au,1),0x55)
local ax=av+aw

local ay=bit32.band(ax,aq)
local az=bit32.band(bit32.rshift(ax,2),aq)
local aA=ay-az
local aB=if aA<0 then aA+ar else aA

local aC=bit32.band(bit32.rshift(ax,4),aq)
local aD=bit32.band(bit32.rshift(ax,6),aq)
local aE=aC-aD
local aF=if aE<0 then aE+ar else aE

buffer.writeu16(an,ap+at*2,aB)
buffer.writeu16(an,ap+(at+1)*2,aF)
end
end

local function SamplePolyCbd3(am:buffer,an:buffer,ao:number?)
local ap=ao or 0
local aq=0x249249
local ar=0x07
local as=ah

for at=0,63 do
local au=at*3
local av=at*4

local aw=buffer.readu8(am,au)
local ax=buffer.readu8(am,au+1)
local ay=buffer.readu8(am,au+2)
local az=bit32.bor(aw,bit32.lshift(ax,8),bit32.lshift(ay,16))

local aA=bit32.band(az,aq)
local aB=bit32.band(bit32.rshift(az,1),aq)
local aC=bit32.band(bit32.rshift(az,2),aq)
local aD=aA+aB+aC

for aE=0,3 do
local aF=aE*6
local aG=bit32.band(bit32.rshift(aD,aF),ar)
local aH=bit32.band(bit32.rshift(aD,aF+3),ar)
local aI=aG-aH
local aJ=if aI<0 then aI+as else aI

buffer.writeu16(an,ap+(av+aE)*2,aJ)
end
end
end

local function SampleNtt(am:buffer,an:buffer)
local ao=0
local ap=ai

ad.Reset128()
ad.Absorb128(am)

while ao<af do
ad.Squeeze128Into(ap,168,0)
local aq=0

while aq+2<168 and ao<af do
local ar=buffer.readu8(ap,aq)
local as=buffer.readu8(ap,aq+1)
local at=buffer.readu8(ap,aq+2)

local au=bit32.bor(ar,bit32.lshift(bit32.band(as,0x0F),8))
local av=bit32.bor(bit32.rshift(as,4),bit32.lshift(at,4))

if au<ah then
buffer.writeu16(an,ao*2,au)
ao+=1
end

if av<ah and ao<af then
buffer.writeu16(an,ao*2,av)
ao+=1
end

aq+=3
end
end
end

local am={}

function am.GenerateMatrix(an:number,ao:buffer,ap:boolean):buffer
local aq=aa.MatCreate(an,an)
local ar=buffer.create(34)
buffer.copy(ar,0,ao,0,32)

local as=ag
local at=aj
local au=SampleNtt

for av=0,an-1 do
for aw=0,an-1 do
if ap then
buffer.writeu8(ar,32,av)
buffer.writeu8(ar,33,aw)
else
buffer.writeu8(ar,32,aw)
buffer.writeu8(ar,33,av)
end

au(ar,at)
local ax=(av*an+aw)*as
buffer.copy(aq,ax,at,0,as)
end
end

return aq
end

function am.SamplePolyCbd(an:buffer,ao:number):buffer
local ap=buffer.create(af*2)

if ao==2 then
SamplePolyCbd2(an,ap,0)
else
SamplePolyCbd3(an,ap,0)
end

return ap
end

function am.GenerateVector(an:number,ao:number,ap:buffer,aq:number):buffer
local ar=aa.VecCreate(an)
local as=al
local at=ak
buffer.copy(as,0,ap,0,32)

local au=ag
local av=64*ao

for aw=0,an-1 do
buffer.writeu8(as,32,aq+aw)

ad.Reset256()
ad.Absorb256(as)
ad.Squeeze256Into(at,av,0)

local ax=aw*au
if ao==2 then
SamplePolyCbd2(at,ar,ax)
else
SamplePolyCbd3(at,ar,ax)
end
end

return ar
end

function am.GenerateNoisePoly(an:number,ao:buffer,ap:number):buffer
if not ab.CheckEta(an)then
error"Invalid eta parameter"
end
if buffer.len(ao)~=32 then
error"Sigma must be 32 bytes"
end

local aq=buffer.create(33)
buffer.copy(aq,0,ao,0,32)
buffer.writeu8(aq,32,ap)

local ar=ac.SHAKE256(aq,64*an)
return am.SamplePolyCbd(ar,an)
end

return am end function a.aq():typeof(__modImpl())local aa=a.cache.aq if not aa then aa={c=__modImpl()}a.cache.aq=aa end return aa.c end end do local function __modImpl()
























local aa=a.ak()

local ab=a.an()
local ac=a.aq()

local ad=a.al()
local ae=a.am()

local af=a.ai()
local ag=a.aj()
local ah=a.ao()

local ai=8
local aj=2^ai
local ak=aj*2

local al=buffer.create(aj*2)
local am=buffer.create(aj*2)
local an=buffer.create(aj*2)
local ao=buffer.create(aj*2)
local ap=buffer.create(aj*2)
local aq=buffer.create(aj*2)
local ar=buffer.create(aj*2)

local as=buffer.create(33)
local at=buffer.create(32)
local au=buffer.create(32)

local av={}

function av.KeyGen(aw:number,ax:number,ay:buffer):(buffer,buffer)
if not af.CheckKeygenParams(aw,ax)then
error"Invalid keygen parameters"
end
if buffer.len(ay)~=32 then
error"Seed must be 32 bytes"
end

local az=as
buffer.copy(az,0,ay,0,32)
buffer.writeu8(az,32,aw)

local aA=ah.SHA3_512(az)
local aB=at
local aC=au
buffer.copy(aB,0,aA,0,32)
buffer.copy(aC,0,aA,32,32)

local aD=ac.GenerateMatrix(aw,aB,false)

local aE=0
local aF=ac.GenerateVector(aw,ax,aC,aE)
aE+=aw
local aG=ac.GenerateVector(aw,ax,aC,aE)

ab.VecNtt(aF,aw)
ab.VecNtt(aG,aw)

local aH=ab.VecCreate(aw)
ab.MatVecMultiply(aD,aF,aH,aw,aw,aw)
ab.VecAddTo(aG,aH,aw)

local aI=ag.GetPkePublicKeyLen(aw)
local aJ=buffer.create(aI)

local aK=ab.VecEncode(aH,aw,12)
local aL=aw*12*32
buffer.copy(aJ,0,aK,0,aL)
buffer.copy(aJ,aL,aB,0,32)

return aJ,ab.VecEncode(aF,aw,12)
end

function av.Encrypt(aw:number,ax:number,ay:number,az:number,aA:number,aB:buffer,aC:buffer,aD:buffer):buffer
if not af.CheckEncryptParams(aw,ax,ay,az,aA)then
error"Invalid encryption parameters"
end
if buffer.len(aB)~=ag.GetPkePublicKeyLen(aw)then
error"Invalid public key length"
end
if buffer.len(aC)~=32 then
error"Message must be 32 bytes"
end
if buffer.len(aD)~=32 then
error"Randomness must be 32 bytes"
end

local aE=aw*12*32
local aF=buffer.create(aE)
local aG=buffer.create(32)
buffer.copy(aF,0,aB,0,aE)
buffer.copy(aG,0,aB,aE,32)

local aH=ab.VecDecode(aF,aw,12)
local aI=ab.VecEncode(aH,aw,12)
local aJ=ag.CtMemcmp(aF,aI)
if aJ~=0xFFFFFFFF then
error"Key encapsulation verification failed"
end

local aK=ac.GenerateMatrix(aw,aG,true)

local aL=0
local aM=ac.GenerateVector(aw,ax,aD,aL)
aL+=aw
local aN=ac.GenerateVector(aw,ay,aD,aL)
aL+=aw
local aO=ac.GenerateNoisePoly(ay,aD,aL)

ab.VecNtt(aM,aw)

local aP=ab.VecCreate(aw)
ab.MatVecMultiply(aK,aM,aP,aw,aw,aw)

ab.VecIntt(aP,aw)
ab.VecAddTo(aN,aP,aw)

local aQ=al
local aR=am
local aS=an
local aT=ao
buffer.fill(aQ,0,0,aj*2)

local aU=ak
for aV=0,aw-1 do
local b=aV*aU
local c=aV*aU
buffer.copy(aS,0,aH,b,aU)
buffer.copy(aT,0,aM,c,aU)
aa.PolyMul(aS,aT,aR)
aa.PolyAdd(aQ,aR,aQ)
end

aa.Intt(aQ)
aa.PolyAdd(aQ,aO,aQ)

local aV=ad.Decode(aC,1)
ae.PolyDecompress(aV,1)
aa.PolyAdd(aQ,aV,aQ)

ab.VecCompress(aP,aw,az)
local b=ab.VecEncode(aP,aw,az)

ae.PolyCompress(aQ,aA)
local c=ad.Encode(aQ,aA)

local d=ag.GetPkeCipherTextLen(aw,az,aA)
local e=buffer.create(d)
local f=buffer.len(b)
buffer.copy(e,0,b,0,f)
buffer.copy(e,f,c,0,buffer.len(c))

return e
end

function av.Decrypt(aw:number,ax:number,ay:number,az:buffer,aA:buffer):buffer
if not af.CheckDecryptParams(aw,ax,ay)then
error"Invalid decryption parameters"
end
if buffer.len(az)~=ag.GetPkeSecretKeyLen(aw)then
error"Invalid secret key length"
end
if buffer.len(aA)~=ag.GetPkeCipherTextLen(aw,ax,ay)then
error"Invalid ciphertext length"
end

local aB=aw*ax*32
local aC=ay*32

local aD=buffer.create(aB)
local aE=buffer.create(aC)
buffer.copy(aD,0,aA,0,aB)
buffer.copy(aE,0,aA,aB,aC)

local aF=ab.VecDecode(aD,aw,ax)
ab.VecDecompress(aF,aw,ax)

local aG=ad.Decode(aE,ay)
ae.PolyDecompress(aG,ay)

local aH=ab.VecDecode(az,aw,12)

ab.VecNtt(aF,aw)

local aI=ap
local aJ=aq
local aK=an
local aL=ar
buffer.fill(aI,0,0,aj*2)

local aM=ak
for aN=0,aw-1 do
local aO=aN*aM
local aP=aN*aM

buffer.copy(aK,0,aH,aO,aM)
buffer.copy(aL,0,aF,aP,aM)

aa.PolyMul(aK,aL,aJ)
aa.PolyAdd(aI,aJ,aI)
end

aa.Intt(aI)
aa.PolySub(aG,aI,aG)

ae.PolyCompress(aG,1)
local aN=ad.Encode(aG,1)

return aN
end

av.MLKEM_512={
KeyGen=function(aw:buffer):(buffer,buffer)
return av.KeyGen(2,3,aw)
end,

Encrypt=function(aw:buffer,ax:buffer,ay:buffer):buffer
return av.Encrypt(2,3,2,10,4,aw,ax,ay)
end,

Decrypt=function(aw:buffer,ax:buffer):buffer
return av.Decrypt(2,10,4,aw,ax)
end
}

av.MLKEM_768={
KeyGen=function(aw:buffer):(buffer,buffer)
return av.KeyGen(3,2,aw)
end,

Encrypt=function(aw:buffer,ax:buffer,ay:buffer):buffer
return av.Encrypt(3,2,2,10,4,aw,ax,ay)
end,

Decrypt=function(aw:buffer,ax:buffer):buffer
return av.Decrypt(3,10,4,aw,ax)
end
}

av.MLKEM_1024={
KeyGen=function(aw:buffer):(buffer,buffer)
return av.KeyGen(4,2,aw)
end,

Encrypt=function(aw:buffer,ax:buffer,ay:buffer):buffer
return av.Encrypt(4,2,2,11,5,aw,ax,ay)
end,

Decrypt=function(aw:buffer,ax:buffer):buffer
return av.Decrypt(4,11,5,aw,ax)
end
}

return av end function a.ar():typeof(__modImpl())local aa=a.cache.ar if not aa then aa={c=__modImpl()}a.cache.ar=aa end return aa.c end end do local function __modImpl()













local aa=buffer.create(512)do
local ab="0123456789abcdef"
for ac=0,255 do
local ad=bit32.rshift(ac,4)
local ae=ac%16

local af=string.byte(ab,ad+1)
local ag=string.byte(ab,ae+1)

local ah=af+bit32.lshift(ag,8)
buffer.writeu16(aa,ac*2,ah)
end
end

local ab=buffer.create(131072)do
for ac=0,255 do
for ad=0,255 do
local ae=0
local af=0

if ac>=48 and ac<=57 then
ae=ac-48
elseif ac>=65 and ac<=70 then
ae=ac-55
elseif ac>=97 and ac<=102 then
ae=ac-87
else
ae=0
end

if ad>=48 and ad<=57 then
af=ad-48
elseif ad>=65 and ad<=70 then
af=ad-55
elseif ad>=97 and ad<=102 then
af=ad-87
else
af=0
end

local ag=bit32.lshift(ae,4)+af
local ah=bit32.lshift(ad,8)+ac
buffer.writeu16(ab,ah*2,ag)
end
end
end

local ac={}

function ac.ToHex(ad:buffer):string
local ae=buffer.len(ad)
local af=buffer.create(ae*2)

local ag=aa

local ah=ae%8
local ai=0

for aj=0,ae-ah-1,8 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
local al=buffer.readu16(ag,buffer.readu8(ad,aj+1)*2)
local am=buffer.readu16(ag,buffer.readu8(ad,aj+2)*2)
local an=buffer.readu16(ag,buffer.readu8(ad,aj+3)*2)
local ao=buffer.readu16(ag,buffer.readu8(ad,aj+4)*2)
local ap=buffer.readu16(ag,buffer.readu8(ad,aj+5)*2)
local aq=buffer.readu16(ag,buffer.readu8(ad,aj+6)*2)
local ar=buffer.readu16(ag,buffer.readu8(ad,aj+7)*2)

buffer.writeu16(af,ai,ak)
buffer.writeu16(af,ai+2,al)
buffer.writeu16(af,ai+4,am)
buffer.writeu16(af,ai+6,an)
buffer.writeu16(af,ai+8,ao)
buffer.writeu16(af,ai+10,ap)
buffer.writeu16(af,ai+12,aq)
buffer.writeu16(af,ai+14,ar)

ai+=16
end

for aj=ae-ah,ae-1 do
local ak=buffer.readu16(ag,buffer.readu8(ad,aj)*2)
buffer.writeu16(af,ai,ak)
ai+=2
end

return buffer.tostring(af)
end

function ac.FromHex(ad:string|buffer):buffer
local ae=if type(ad)=="string"then buffer.fromstring(ad)else ad
local af=buffer.len(ae)
if af%2~=0 then
error(`Length must be even, got {af}`)
end

local ag=buffer.create(bit32.rshift(af,1))
local ah=af%16
local ai=0
local aj=ab

for ak=0,af-ah-1,16 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(ae,ak+2)
local an=buffer.readu16(ae,ak+4)
local ao=buffer.readu16(ae,ak+6)
local ap=buffer.readu16(ae,ak+8)
local aq=buffer.readu16(ae,ak+10)
local ar=buffer.readu16(ae,ak+12)
local as=buffer.readu16(ae,ak+14)

local at=buffer.readu16(aj,al*2)
local au=buffer.readu16(aj,am*2)
local av=buffer.readu16(aj,an*2)
local aw=buffer.readu16(aj,ao*2)
local ax=buffer.readu16(aj,ap*2)
local ay=buffer.readu16(aj,aq*2)
local az=buffer.readu16(aj,ar*2)
local aA=buffer.readu16(aj,as*2)

local aB=bit32.lshift(aw,24)+bit32.lshift(av,16)+
bit32.lshift(au,8)+at
local aC=bit32.lshift(aA,24)+bit32.lshift(az,16)+
bit32.lshift(ay,8)+ax

buffer.writeu32(ag,ai,aB)
buffer.writeu32(ag,ai+4,aC)
ai+=8
end

for ak=af-ah,af-1,2 do
local al=buffer.readu16(ae,ak)
local am=buffer.readu16(aj,al*2)
buffer.writeu8(ag,ai,am)
ai+=1
end

return ag
end

return ac end function a.as():typeof(__modImpl())local aa=a.cache.as if not aa then aa={c=__modImpl()}a.cache.as=aa end return aa.c end end do local function __modImpl()
























local aa=4
local ab=64
local ac=16

local ad=12
local ae=16
local af=32

local ag=buffer.create(16)do
local ah={string.byte("expand 32-byte k",1,-1)}
for ai,aj in ah do
buffer.writeu8(ag,ai-1,aj)
end
end

local ah=buffer.create(16)do
local ai={string.byte("expand 16-byte k",1,-1)}
for aj,ak in ai do
buffer.writeu8(ah,aj-1,ak)
end
end

local function ProcessBlock(ai:buffer,aj:number)
local ak:number,al:number,am:number,an:number,ao:number,ap:number,aq:number,ar:number,as:number,at:number,au:number,av:number,aw:number,ax:number,ay:number,az:number=
buffer.readu32(ai,0),buffer.readu32(ai,4),
buffer.readu32(ai,8),buffer.readu32(ai,12),
buffer.readu32(ai,16),buffer.readu32(ai,20),
buffer.readu32(ai,24),buffer.readu32(ai,28),
buffer.readu32(ai,32),buffer.readu32(ai,36),
buffer.readu32(ai,40),buffer.readu32(ai,44),
buffer.readu32(ai,48),buffer.readu32(ai,52),
buffer.readu32(ai,56),buffer.readu32(ai,60)

for aA=1,aj do
local aB=aA%2==1

if aB then
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),16)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),12)
ak=bit32.bor(ak+ao,0);aw=bit32.lrotate(bit32.bxor(aw,ak),8)
as=bit32.bor(as+aw,0);ao=bit32.lrotate(bit32.bxor(ao,as),7)

al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),16)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),12)
al=bit32.bor(al+ap,0);ax=bit32.lrotate(bit32.bxor(ax,al),8)
at=bit32.bor(at+ax,0);ap=bit32.lrotate(bit32.bxor(ap,at),7)

am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),16)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),12)
am=bit32.bor(am+aq,0);ay=bit32.lrotate(bit32.bxor(ay,am),8)
au=bit32.bor(au+ay,0);aq=bit32.lrotate(bit32.bxor(aq,au),7)

an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),16)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),12)
an=bit32.bor(an+ar,0);az=bit32.lrotate(bit32.bxor(az,an),8)
av=bit32.bor(av+az,0);ar=bit32.lrotate(bit32.bxor(ar,av),7)
else
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),16)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),12)
ak=bit32.bor(ak+ap,0);az=bit32.lrotate(bit32.bxor(az,ak),8)
au=bit32.bor(au+az,0);ap=bit32.lrotate(bit32.bxor(ap,au),7)

al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),16)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),12)
al=bit32.bor(al+aq,0);aw=bit32.lrotate(bit32.bxor(aw,al),8)
av=bit32.bor(av+aw,0);aq=bit32.lrotate(bit32.bxor(aq,av),7)

am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),16)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),12)
am=bit32.bor(am+ar,0);ax=bit32.lrotate(bit32.bxor(ax,am),8)
as=bit32.bor(as+ax,0);ar=bit32.lrotate(bit32.bxor(ar,as),7)

an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),16)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),12)
an=bit32.bor(an+ao,0);ay=bit32.lrotate(bit32.bxor(ay,an),8)
at=bit32.bor(at+ay,0);ao=bit32.lrotate(bit32.bxor(ao,at),7)
end
end

buffer.writeu32(ai,0,buffer.readu32(ai,0)+ak)
buffer.writeu32(ai,4,buffer.readu32(ai,4)+al)
buffer.writeu32(ai,8,buffer.readu32(ai,8)+am)
buffer.writeu32(ai,12,buffer.readu32(ai,12)+an)
buffer.writeu32(ai,16,buffer.readu32(ai,16)+ao)
buffer.writeu32(ai,20,buffer.readu32(ai,20)+ap)
buffer.writeu32(ai,24,buffer.readu32(ai,24)+aq)
buffer.writeu32(ai,28,buffer.readu32(ai,28)+ar)
buffer.writeu32(ai,32,buffer.readu32(ai,32)+as)
buffer.writeu32(ai,36,buffer.readu32(ai,36)+at)
buffer.writeu32(ai,40,buffer.readu32(ai,40)+au)
buffer.writeu32(ai,44,buffer.readu32(ai,44)+av)
buffer.writeu32(ai,48,buffer.readu32(ai,48)+aw)
buffer.writeu32(ai,52,buffer.readu32(ai,52)+ax)
buffer.writeu32(ai,56,buffer.readu32(ai,56)+ay)
buffer.writeu32(ai,60,buffer.readu32(ai,60)+az)
end

local function InitializeState(ai:buffer,aj:buffer,ak:number):buffer
local al=buffer.len(ai)
local am=buffer.create(ac*aa)

local an=al==32 and ag or ah

buffer.copy(am,0,an,0,16)

buffer.copy(am,16,ai,0,math.min(al,16))
if al==32 then
buffer.copy(am,32,ai,16,16)
else
buffer.copy(am,32,ai,0,16)
end

buffer.writeu32(am,48,ak)
buffer.copy(am,52,aj,0,12)

return am
end

local function ChaCha20(ai:buffer,aj:buffer,ak:buffer,al:number?,am:number?):buffer
if ai==nil then
error("Data cannot be nil",2)
end

if typeof(ai)~="buffer"then
error(`Data must be a buffer, got {typeof(ai)}`,2)
end

if aj==nil then
error("Key cannot be nil",2)
end

if typeof(aj)~="buffer"then
error(`Key must be a buffer, got {typeof(aj)}`,2)
end

local an=buffer.len(aj)
if an~=ae and an~=af then
error(`Key must be {ae} or {af} bytes long, got {an} bytes`,2)
end

if ak==nil then
error("Nonce cannot be nil",2)
end

if typeof(ak)~="buffer"then
error(`Nonce must be a buffer, got {typeof(ak)}`,2)
end

local ao=buffer.len(ak)
if ao~=ad then
error(`Nonce must be exactly {ad} bytes long, got {ao} bytes`,2)
end

if al then
if typeof(al)~="number"then
error(`Counter must be a number, got {typeof(al)}`,2)
end

if al<0 then
error(`Counter cannot be negative, got {al}`,2)
end

if al~=math.floor(al)then
error(`Counter must be an integer, got {al}`,2)
end

if al>=4294967296 then
error(`Counter must be less than 2^32, got {al}`,2)
end
end

if am then
if typeof(am)~="number"then
error(`Rounds must be a number, got {typeof(am)}`,2)
end

if am<=0 then
error(`Rounds must be positive, got {am}`,2)
end

if am~=math.floor(am)then
error(`Rounds must be an integer, got {am}`,2)
end

if am%2~=0 then
error(`Rounds must be even, got {am}`,2)
end
end

local ap=al or 1
local aq=am or 20

local ar=buffer.len(ai)
if ar==0 then
return buffer.create(0)
end

local as=buffer.create(ar)

local at=0

local au=InitializeState(aj,ak,ap)
local av=buffer.create(64)
buffer.copy(av,0,au,0)

while at<ar do
ProcessBlock(au,aq)

local aw=math.min(ab,ar-at)

for ax=0,aw-1 do
local ay=buffer.readu8(ai,at+ax)
local az=buffer.readu8(au,ax)
buffer.writeu8(as,at+ax,bit32.bxor(ay,az))
end

at+=aw
ap+=1
buffer.copy(au,0,av,0)
buffer.writeu32(au,48,ap)
end

return as
end

return ChaCha20 end function a.at():typeof(__modImpl())local aa=a.cache.at if not aa then aa={c=__modImpl()}a.cache.at=aa end return aa.c end end do local function __modImpl()




























local aa=64
local ab=32
local ac=64
local ad=64
local ae=ad*ab

local af=0x01
local ag=0x02
local ah=0x04
local ai=0x08

local aj=buffer.create(ab)do
local ak={
0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
}
for al,am in ipairs(ak)do
buffer.writeu32(aj,(al-1)*4,am)
end
end

local function Compress(ak:buffer,al:buffer,am:number,an:number,ao:number,ap:boolean?):buffer
local aq=buffer.readu32(ak,0)
local ar=buffer.readu32(ak,4)
local as=buffer.readu32(ak,8)
local at=buffer.readu32(ak,12)
local au=buffer.readu32(ak,16)
local av=buffer.readu32(ak,20)
local aw=buffer.readu32(ak,24)
local ax=buffer.readu32(ak,28)

local ay,az,aA,aB=aq,ar,as,at
local aC,aD,aE,aF=au,av,aw,ax
local aG,aH,aI,aJ=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a

local aK=am%(4294967296)
local aL=(am-aK)*(2.3283064365386963E-10)

local aM=buffer.readu32(al,0)
local aN=buffer.readu32(al,4)
local aO=buffer.readu32(al,8)
local aP=buffer.readu32(al,12)
local aQ=buffer.readu32(al,16)
local aR=buffer.readu32(al,20)
local aS=buffer.readu32(al,24)
local aT=buffer.readu32(al,28)
local aU=buffer.readu32(al,32)
local aV=buffer.readu32(al,36)
local b=buffer.readu32(al,40)
local c=buffer.readu32(al,44)
local d=buffer.readu32(al,48)
local e=buffer.readu32(al,52)
local f=buffer.readu32(al,56)
local g=buffer.readu32(al,60)

local h
for i=1,7 do
ay+=aC+aM;aK=bit32.lrotate(bit32.bxor(aK,ay),16)
aG+=aK;aC=bit32.lrotate(bit32.bxor(aC,aG),20)
ay+=aC+aN;aK=bit32.lrotate(bit32.bxor(aK,ay),24)
aG+=aK;aC=bit32.lrotate(bit32.bxor(aC,aG),25)

az+=aD+aO;aL=bit32.lrotate(bit32.bxor(aL,az),16)
aH+=aL;aD=bit32.lrotate(bit32.bxor(aD,aH),20)
az+=aD+aP;aL=bit32.lrotate(bit32.bxor(aL,az),24)
aH+=aL;aD=bit32.lrotate(bit32.bxor(aD,aH),25)

aA+=aE+aQ;an=bit32.lrotate(bit32.bxor(an,aA),16)
aI+=an;aE=bit32.lrotate(bit32.bxor(aE,aI),20)
aA+=aE+aR;an=bit32.lrotate(bit32.bxor(an,aA),24)
aI+=an;aE=bit32.lrotate(bit32.bxor(aE,aI),25)

aB+=aF+aS;ao=bit32.lrotate(bit32.bxor(ao,aB),16)
aJ+=ao;aF=bit32.lrotate(bit32.bxor(aF,aJ),20)
aB+=aF+aT;ao=bit32.lrotate(bit32.bxor(ao,aB),24)
aJ+=ao;aF=bit32.lrotate(bit32.bxor(aF,aJ),25)

ay+=aD+aU;ao=bit32.lrotate(bit32.bxor(ao,ay),16)
aI+=ao;aD=bit32.lrotate(bit32.bxor(aD,aI),20)
ay+=aD+aV;ao=bit32.lrotate(bit32.bxor(ao,ay),24)
aI+=ao;aD=bit32.lrotate(bit32.bxor(aD,aI),25)

az+=aE+b;aK=bit32.lrotate(bit32.bxor(aK,az),16)
aJ+=aK;aE=bit32.lrotate(bit32.bxor(aE,aJ),20)
az+=aE+c;aK=bit32.lrotate(bit32.bxor(aK,az),24)
aJ+=aK;aE=bit32.lrotate(bit32.bxor(aE,aJ),25)

aA+=aF+d;aL=bit32.lrotate(bit32.bxor(aL,aA),16)
aG+=aL;aF=bit32.lrotate(bit32.bxor(aF,aG),20)
aA+=aF+e;aL=bit32.lrotate(bit32.bxor(aL,aA),24)
aG+=aL;aF=bit32.lrotate(bit32.bxor(aF,aG),25)

aB+=aC+f;an=bit32.lrotate(bit32.bxor(an,aB),16)
aH+=an;aC=bit32.lrotate(bit32.bxor(aC,aH),20)
aB+=aC+g;an=bit32.lrotate(bit32.bxor(an,aB),24)
aH+=an;aC=bit32.lrotate(bit32.bxor(aC,aH),25)

if i~=7 then
h=aO
aO=aP
aP=b
b=d
d=aV
aV=c
c=aR
aR=aM
aM=h

h=aS
aS=aQ
aQ=aT
aT=e
e=f
f=g
g=aU
aU=aN
aN=h
end
end

if ap then
local i=buffer.create(ac)
buffer.writeu32(i,0,bit32.bxor(ay,aG))
buffer.writeu32(i,4,bit32.bxor(az,aH))
buffer.writeu32(i,8,bit32.bxor(aA,aI))
buffer.writeu32(i,12,bit32.bxor(aB,aJ))
buffer.writeu32(i,16,bit32.bxor(aC,aK))
buffer.writeu32(i,20,bit32.bxor(aD,aL))
buffer.writeu32(i,24,bit32.bxor(aE,an))
buffer.writeu32(i,28,bit32.bxor(aF,ao))

buffer.writeu32(i,32,bit32.bxor(aG,aq))
buffer.writeu32(i,36,bit32.bxor(aH,ar))
buffer.writeu32(i,40,bit32.bxor(aI,as))
buffer.writeu32(i,44,bit32.bxor(aJ,at))
buffer.writeu32(i,48,bit32.bxor(aK,au))
buffer.writeu32(i,52,bit32.bxor(aL,av))
buffer.writeu32(i,56,bit32.bxor(an,aw))
buffer.writeu32(i,60,bit32.bxor(ao,ax))

return i
else
local i=buffer.create(ab)
buffer.writeu32(i,0,bit32.bxor(ay,aG))
buffer.writeu32(i,4,bit32.bxor(az,aH))
buffer.writeu32(i,8,bit32.bxor(aA,aI))
buffer.writeu32(i,12,bit32.bxor(aB,aJ))
buffer.writeu32(i,16,bit32.bxor(aC,aK))
buffer.writeu32(i,20,bit32.bxor(aD,aL))
buffer.writeu32(i,24,bit32.bxor(aE,an))
buffer.writeu32(i,28,bit32.bxor(aF,ao))

return i
end
end

local function ProcessMessage(ak:buffer,al:number,am:buffer,an:number):buffer
local ao=buffer.len(am)
local ap=buffer.create(ae)
local aq=0
local ar=buffer.create(ab)
buffer.copy(ar,0,ak,0,ab)

local as=0
local at=0
local au=0
local av=af

local aw=buffer.create(aa)

for ax=0,ao-aa-1,aa do
buffer.copy(aw,0,am,ax,aa)
local ay=al+av+au

ar=Compress(ar,aw,as,aa,ay)
av=0
at+=1

if at==15 then
au=ag
elseif at==16 then
local az=ar
local aA=as+1

while aA%2==0 do
aq=aq-1
local aB=buffer.create(ab)
buffer.copy(aB,0,ap,aq*ab,ab)

local aC=buffer.create(ac)
buffer.copy(aC,0,aB,0,ab)
buffer.copy(aC,ab,az,0,ab)

az=Compress(ak,aC,0,aa,al+ah)
aA=aA/2
end

buffer.copy(ap,aq*ab,az,0,ab)
aq=aq+1
buffer.copy(ar,0,ak,0,ab)
av=af

as+=1
at=0
au=0
end
end

local ax=ao==0 and 0 or((ao-1)%aa+1)
local ay=buffer.create(aa)

if ax>0 then
buffer.copy(ay,0,am,ao-ax,ax)
end

local az:buffer
local aA:buffer
local aB:number
local aC:number

if as>0 then
local aD=al+av+ag
local aE=Compress(ar,ay,as,ax,aD)

for aF=aq,2,-1 do
local aG=buffer.create(ab)
buffer.copy(aG,0,ap,(aF-1)*ab,ab)

local aH=buffer.create(ac)
buffer.copy(aH,0,aG,0,ab)
buffer.copy(aH,ab,aE,0,ab)

aE=Compress(ak,aH,0,aa,al+ah)
end

az=ak
local aF=buffer.create(ab)
buffer.copy(aF,0,ap,0,ab)

aA=buffer.create(ac)
buffer.copy(aA,0,aF,0,ab)
buffer.copy(aA,ab,aE,0,ab)

aB=aa
aC=al+ai+ah
else
az=ar
aA=ay
aB=ax
aC=al+av+ag+ai
end

local aD=buffer.create(an)
local aE=0

for aF=0,an//aa do
local aG=Compress(az,aA,aF,aB,aC,true)

local aH=math.min(aa,an-aE)
buffer.copy(aD,aE,aG,0,aH)
aE+=aH

if aE>=an then
break
end
end

return aD
end

return function(ak:buffer,al:number?):buffer
return ProcessMessage(aj,0,ak,al or 32)
end end function a.au():typeof(__modImpl())local aa=a.cache.au if not aa then aa={c=__modImpl()}a.cache.au=aa end return aa.c end end do local function __modImpl()


























local aa=a.as()
local ab=a.at()
local ac=a.au()


































local ad=64
local ae=32
local af=12

local ag:CSPRNGModule__DARKLUA_TYPE_k={
BlockExpansion=true,
SizeTarget=2048,
RekeyAfter=1024,

Key=buffer.create(0),
Nonce=buffer.create(0),
Buffer=buffer.create(0),

Counter=0,
BufferPosition=0,
BufferSize=0,
BytesLeft=0,

EntropyProviders={}
}::CSPRNGModule__DARKLUA_TYPE_k

local ah=buffer.create(ad)
local ai=math.max(math.floor(ag.RekeyAfter),2)
local aj=math.clamp(math.floor(ag.SizeTarget),64,4294967295)

local function Reset()
ag.Key=buffer.create(0)
ag.Nonce=buffer.create(0)
ag.Buffer=buffer.create(0)

ag.Counter=0
ag.BufferPosition=0
ag.BufferSize=0
end

local function GatherEntropy(ak:buffer?):number
local al=buffer.create(1024)
local am=0

local function WriteToBuffer(an:buffer)
local ao=buffer.len(an)
buffer.copy(al,am,an,0,ao)
am+=ao
end

local an=1.234
if tick then
an=tick()
local ao=buffer.create(8)
buffer.writef64(ao,0,an)
WriteToBuffer(ao)
end

local ao=os.clock()
local ap=buffer.create(8)
buffer.writef64(ap,0,ao)
WriteToBuffer(ap)

local aq=os.time()
local ar=buffer.create(8)
buffer.writeu32(ar,0,aq%0x100000000)
buffer.writeu32(ar,4,math.floor(aq/0x100000000))
WriteToBuffer(ar)

local as=5.678
if DateTime then
as=DateTime.now().UnixTimestampMillis
local at=buffer.create(8)
buffer.writef64(at,0,as)
WriteToBuffer(at)

local au=buffer.create(16)
buffer.writef32(au,0,as/1000)
buffer.writef32(au,4,(as%1000)/100)
buffer.writef32(au,8,as/86400000)
buffer.writef32(au,12,(as*0.001)%1)
WriteToBuffer(au)
else
WriteToBuffer(buffer.create(24))
end

local at=buffer.create(16)
buffer.writef32(at,0,ao/100)
buffer.writef32(at,4,an/1000)
buffer.writef32(at,8,(ao*12345.6789)%1)
buffer.writef32(at,12,(an*98765.4321)%1)
WriteToBuffer(at)

local au=buffer.create(32)
for av=0,7 do
local aw=math.noise(ao+av,aq+av,ao+aq+av)
local ax=math.noise(an+av*0.1,as*0.0001+av,ao*1.5+av)
local ay=math.noise(aq*0.01+av,ao+as*0.001,an+av*2)
local az=math.noise(as*0.00001+av,aq+ao+av,an*0.1+av)

buffer.writef32(au,av*4,aw+ax+ay+az)
end
WriteToBuffer(au)

local av=buffer.create(32)
for aw=0,7 do
local ax=os.clock()
local ay=0

local az=50+(aw*25)
for aA=1,az do
ay+=aA*aA+math.sin(aA/10)*math.cos(aA/7)
end

local aA=os.clock()
local aB=aA-ax
buffer.writef32(av,aw*4,aB*1000000)
end
WriteToBuffer(av)

local aw=buffer.create(24)
for ax=0,5 do
local ay=os.clock()

for az=1,20 do
buffer.create(64+az)
end

local az=os.clock()
buffer.writef32(aw,ax*4,(az-ay)*10000000)
end
WriteToBuffer(aw)

local ax=math.floor(an*1000000)
local ay=buffer.create(8)
buffer.writeu32(ay,0,ax%0x100000000)
buffer.writeu32(ay,4,math.floor(ax/0x100000000))
WriteToBuffer(ay)

if game then
if game.JobId and#game.JobId>0 then
local az=buffer.fromstring(game.JobId)
WriteToBuffer(az)
end

if game.PlaceId then
local az=buffer.create(8)
buffer.writeu32(az,0,game.PlaceId%0x100000000)
buffer.writeu32(az,4,math.floor(game.PlaceId/0x100000000))
WriteToBuffer(az)
end

if workspace and workspace.DistributedGameTime then
local az=buffer.create(8)
buffer.writef64(az,0,workspace.DistributedGameTime)
WriteToBuffer(az)

local aA=math.floor(workspace.DistributedGameTime*1000000)
local aB=buffer.create(8)
buffer.writeu32(aB,0,aA%0x100000000)
buffer.writeu32(aB,4,math.floor(aA/0x100000000))
WriteToBuffer(aB)
end
end

local az=buffer.create(128)
for aA=0,7 do
local aB={}
local aC=function()end
local aD=buffer.create(0)
local aE=newproxy()

local aF=string.gsub(tostring(aB),"table: ","")
local aG=string.gsub(tostring(aC),"function: ","")
local aH=string.gsub(tostring(aD),"buffer: ","")
local aI=string.gsub(tostring(aE),"userdata: ","")

local aJ=0
local aK=0
local aL=0
local aM=0
local aN=0

for aO=1,#aF do
aJ=bit32.bxor(aJ,string.byte(aF,aO))*31
end

if coroutine then
local aO=string.gsub(tostring(coroutine.create(function()end)),"thread: ","")
for aP=1,#aO do
aK=bit32.bxor(aK,string.byte(aO,aP))*31
end
end

for aO=1,#aG do
aL=bit32.bxor(aL,string.byte(aG,aO))*37
end
for aO=1,#aH do
aM=bit32.bxor(aM,string.byte(aH,aO))*41
end
for aO=1,#aI do
aN=bit32.bxor(aN,string.byte(aI,aO))*43
end

buffer.writeu32(az,aA*16,aJ)
buffer.writeu32(az,aA*16+4,aK)
buffer.writeu32(az,aA*16+8,aL)
buffer.writeu32(az,aA*16+12,bit32.bxor(aM,aN))
end
WriteToBuffer(az)

local function AddExtraEntropy(aA:buffer?,aB:boolean,aC:string?)
if not aA then
return
end

local aD=1024-am

if aD>0 then
local aE=buffer.len(aA)-aD
local aF=math.min(aD,buffer.len(aA))

if aE>0 and aB and aC then
warn(`CSPRNG: {aC} returned {aE} bytes more than available and was truncated to {aF} bytes`)
end

buffer.copy(al,am,aA,0,aF)
end
end

for aA,aB in ag.EntropyProviders do
local aC=1024-am
if aC>0 then
local aD:boolean,aE:buffer?=pcall(aB,aC)
if not aD then
warn(`CSPRNG Provider errored with {aE}`)
end

AddExtraEntropy(aE,true,`Entropy Provider #{aA}`)
end
end

if ak then
AddExtraEntropy(ak,false)
end

local aA=ac(al,ae+af)

ag.Key=buffer.create(ae)
buffer.copy(ag.Key,0,aA,0,ae)

ag.Nonce=buffer.create(af)
buffer.copy(ag.Nonce,0,aA,ae,af)

return buffer.len(al)-am
end

local function GenerateBlock()
buffer.fill(ah,0,0,ad)
local ak=ab(ah,ag.Key,ag.Nonce,ag.Counter,20)

ag.Buffer=if ag.BlockExpansion then ac(ak,aj)else ak
ag.BufferPosition=0
ag.BufferSize=buffer.len(ag.Buffer)
ag.Counter+=1

if ag.Counter%ai==0 then
GatherEntropy()
ag.Counter=0
end
end

local function GetBytes(ak:number):buffer
local al=buffer.create(ak)
local am=0

while am<ak do
if ag.BufferPosition>=ag.BufferSize then
GenerateBlock()
end

local an=ak-am
local ao=ag.BufferSize-ag.BufferPosition
local ap=math.min(an,ao)

buffer.copy(al,am,ag.Buffer,ag.BufferPosition,ap)
am+=ap
ag.BufferPosition+=ap
end

return al
end

local function GetFloat():number
if ag.BufferPosition+8>ag.BufferSize then
GenerateBlock()
end

local ak=buffer.readu32(ag.Buffer,ag.BufferPosition)
local al=buffer.readu32(ag.Buffer,ag.BufferPosition+4)
ag.BufferPosition+=8

local am=bit32.rshift(ak,5)
local an=bit32.rshift(al,6)

return(am*67108864.0+an)/9007199254740992.0
end

local function GetIntRange(ak:number,al:number):number
local am=al-ak+1
local an=0xFFFFFFFF
local ao=an-(an%am)

if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end

local ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4

if bit32.band(am,am-1)==0 then
return ak+bit32.band(ap,am-1)
else
while ap>ao do
if ag.BufferPosition+4>ag.BufferSize then
GenerateBlock()
end
ap=buffer.readu32(ag.Buffer,ag.BufferPosition)
ag.BufferPosition+=4
end

return ak+(ap%am)
end
end

local function GetNumberRange(ak:number,al:number):number
if ak>al then
ak,al=al,ak
end

local am=al-ak
if am<=0 then
return ak
end

return ak+(GetFloat()*am)
end

local function GetRandomString(ak:number,al:boolean?):string|buffer
local am=buffer.create(ak)

for an=0,ak-1 do
buffer.writeu8(am,an,GetIntRange(36,122))
end

return if al
then am
else buffer.tostring(am)
end

local function GetEd25519RandomBytes():buffer
local ak=buffer.create(32)

for al=0,31 do
buffer.writeu8(ak,al,GetIntRange(0,255))
end

return ak
end

local function GetEd25519ClampedBytes(ak:buffer):buffer
local al=buffer.create(32)
buffer.copy(al,0,ak,0,32)

local am=buffer.readu8(al,0)
am=bit32.band(am,0xF8)
buffer.writeu8(al,0,am)

local an=buffer.readu8(al,31)
an=bit32.band(an,0x7F)
an=bit32.bor(an,0x40)
buffer.writeu8(al,31,an)

local ao=false
local ap=buffer.readu8(al,1)
for aq=2,30 do
if buffer.readu8(al,aq)~=ap then
ao=true
break
end
end

if not ao then
buffer.writeu8(al,15,bit32.bxor(ap,0x55))
end

return al
end

local function GetHexString(ak:number):string
local al=ak/2
local am=GetBytes(al)
local an=aa.ToHex(am)

return an
end

function ag.AddEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_j)
table.insert(ag.EntropyProviders,ak)
end

function ag.RemoveEntropyProvider(ak:EntropyProvider__DARKLUA_TYPE_j)
for al=#ag.EntropyProviders,1,-1 do
if ag.EntropyProviders[al]==ak then
table.remove(ag.EntropyProviders,al)
break
end
end
end

function ag.Random():number
return GetFloat()
end

function ag.RandomInt(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) can't be less than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=1
else
am=al
an=ak
end

return GetIntRange(an,am)
end

function ag.RandomNumber(ak:number,al:number?):number
if al and type(al)~="number"then
error(`Max must be a number or nil, got {typeof(al)}`,2)
end

if type(ak)~="number"then
error(`Min must be a number, got {typeof(ak)}`,2)
end

if al and al<ak then
error(`Max ({al}) must be bigger than Min ({ak})`,2)
end

if al and al==ak then
error(`Max ({al}) can't be equal to Min ({ak})`,2)
end

local am:number
local an:number

if al==nil then
am=ak
an=0
else
am=al
an=ak
end

return GetNumberRange(an,am)
end

function ag.RandomBytes(ak:number):buffer
if type(ak)~="number"then
error(`Count must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Count must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Count must be an integer",2)
end

return GetBytes(ak)
end

function ag.RandomString(ak:number,al:boolean?):string|buffer
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if al~=nil and type(al)~="boolean"then
error(`AsBuffer must be a boolean or nil, got {typeof(al)}`,2)
end

return GetRandomString(ak,al)
end

function ag.RandomHex(ak:number):string
if type(ak)~="number"then
error(`Length must be a number, got {typeof(ak)}`,2)
end

if ak<=0 then
error(`Length must be bigger than 0, got {ak}`,2)
end

if ak%1~=0 then
error("Length must be an integer",2)
end

if ak%2~=0 then
error(`Length must be even, got {ak}`,2)
end

return GetHexString(ak)
end

function ag.Ed25519ClampedBytes(ak:buffer):buffer
if type(ak)~="buffer"then
error(`Input must be a buffer, got {typeof(ak)}`,2)
end

return GetEd25519ClampedBytes(ak)
end

function ag.Ed25519Random():buffer
return GetEd25519ClampedBytes(GetEd25519RandomBytes())
end

function ag.Reseed(ak:buffer?)
if ak~=nil and type(ak)~="buffer"then
error(`CustomEntropy must be a buffer or nil, got {typeof(ak)}`,2)
end

Reset()
GatherEntropy(ak)
end

ag.BytesLeft=GatherEntropy()
GenerateBlock()

return ag end function a.av():typeof(__modImpl())local aa=a.cache.av if not aa then aa={c=__modImpl()}a.cache.av=aa end return aa.c end end do local function __modImpl()




























local aa=a.ar()
local ab=a.an()
local ac=a.av()
local ad=a.ai()
local ae=a.aj()
local af=a.ao()

local ag=buffer.create(64)
local ah=buffer.create(32)
local ai=buffer.create(32)
local aj=buffer.create(32)

local ak=buffer.create(64)
local al=buffer.create(32)

local am={
CSPRNG=ac
}

function am.KeyGen(an:number,ao:number,ap:buffer,aq:buffer):(buffer,buffer)
if not ad.CheckKeygenParams(an,ao)then
error"Invalid keygen parameters"
end

if buffer.len(ap)~=32 then
error"D must be 32 bytes"
end

if buffer.len(aq)~=32 then
error"Z must be 32 bytes"
end

local ar,as=aa.KeyGen(an,ao,ap)
local at=af.SHA3_256(ar)

local au=ae.GetKemSecretKeyLen(an)
local av=buffer.create(au)

local aw=0

local ax=buffer.len(as)
buffer.copy(av,aw,as,0,ax)
aw=aw+ax

local ay=buffer.len(ar)
buffer.copy(av,aw,ar,0,ay)
aw+=ay

buffer.copy(av,aw,at,0,32)
aw+=32

buffer.copy(av,aw,aq,0,32)

return ar,av
end

function am.Encapsulate(an:buffer,ao:number,ap:number,aq:number,ar:number,as:number,at:buffer):(buffer?,buffer?)
if not ad.CheckEncapParams(ao,ap,aq,ar,as)then
error"Invalid encapsulation parameters"
end

if buffer.len(at)~=ae.GetKemPublicKeyLen(ao)then
error"Invalid public key length"
end

if buffer.len(an)~=32 then
error"Message must be 32 bytes"
end

local au=ao*12*32
local av=buffer.create(au)
buffer.copy(av,0,at,0,au)

local aw=ab.VecDecode(av,ao,12)
local ax=ab.VecEncode(aw,ao,12)

local ay=ae.CtMemcmp(av,ax)
if ay~=0xFFFFFFFF then
error"malformed public key encoding"
end

local az=af.SHA3_256(at)

local aA=ak
buffer.copy(aA,0,an,0,32)
buffer.copy(aA,32,az,0,32)

local aB=af.SHA3_512(aA)

local aC=buffer.create(32)
local aD=al
buffer.copy(aC,0,aB,0,32)
buffer.copy(aD,0,aB,32,32)

local aE=aa.Encrypt(ao,ap,aq,ar,as,at,an,aD)

return aE,aC
end

function am.Decapsulate(an:buffer,ao:number,ap:number,aq:number,ar:number,as:number,at:buffer):buffer
if not ad.CheckDecapParams(ao,ap,aq,ar,as)then
error"Invalid decapsulation parameters"
end
if buffer.len(at)~=ae.GetKemSecretKeyLen(ao)then
error"Invalid secret key length"
end

if buffer.len(an)~=ae.GetKemCipherTextLen(ao,ar,as)then
error"Invalid ciphertext length"
end

local au=ae.GetPkeSecretKeyLen(ao)
local av=ae.GetPkePublicKeyLen(ao)

local aw=buffer.create(au)
local ax=buffer.create(av)
local ay=buffer.create(32)
local az=buffer.create(32)

local aA=0
buffer.copy(aw,0,at,aA,au)
aA+=au

buffer.copy(ax,0,at,aA,av)
aA+=av

buffer.copy(ay,0,at,aA,32)
aA+=32

buffer.copy(az,0,at,aA,32)

local aB=aa.Decrypt(ao,ar,as,aw,an)

local aC=ag
buffer.copy(aC,0,aB,0,32)
buffer.copy(aC,32,ay,0,32)

local aD=af.SHA3_512(aC)

local aE=ah
local aF=ai
buffer.copy(aE,0,aD,0,32)
buffer.copy(aF,0,aD,32,32)

local aG=buffer.create(32+buffer.len(an))
buffer.copy(aG,0,az,0,32)
buffer.copy(aG,32,an,0,buffer.len(an))

local aH=af.SHAKE256(aG,32)
local aI=aj
buffer.copy(aI,0,aH,0,32)

local aJ=aa.Encrypt(ao,ap,aq,ar,as,ax,aB,aF)
local aK=ae.CtMemcmp(an,aJ)

local aL=buffer.create(32)
ae.CtCondMemcpy(aK,aL,aE,aI)

return aL
end

function am.SecretsEqual(an:buffer,ao:buffer):boolean
if buffer.len(an)~=32 or buffer.len(ao)~=32 then
return false
end

return ae.CtMemcmp(an,ao)==0xFFFFFFFF
end

function am.ValidateDecapsulationKey(an:number,ao:buffer):boolean
local ap=ae.GetPkeSecretKeyLen(an)
local aq=ae.GetPkePublicKeyLen(an)

local ar=ap
local as=ap+aq

local at=buffer.create(aq)
local au=buffer.create(32)
buffer.copy(at,0,ao,ar,aq)
buffer.copy(au,0,ao,as,32)

local av=af.SHA3_256(at)
return ae.CtMemcmp(au,av)==0xFFFFFFFF
end

am.MLKEM_512={
KeyGen=function(an:buffer,ao:buffer):(buffer,buffer)
return am.KeyGen(2,3,an,ao)
end,

Encapsulate=function(an:buffer,ao:buffer):(buffer?,buffer?)
return am.Encapsulate(an,2,3,2,10,4,ao)
end,

Decapsulate=function(an:buffer,ao:buffer):buffer
return am.Decapsulate(an,2,3,2,10,4,ao)
end,

GenerateKeys=function():(buffer,buffer)
local an=ac.RandomBytes(32)
local ao=ac.RandomBytes(32)

return am.MLKEM_512.KeyGen(an,ao)
end,

ValidateDecapsulationKey=function(an:buffer):boolean
return am.ValidateDecapsulationKey(2,an)
end
}

am.MLKEM_768={
KeyGen=function(an:buffer,ao:buffer):(buffer,buffer)
return am.KeyGen(3,2,an,ao)
end,

Encapsulate=function(an:buffer,ao:buffer):(buffer?,buffer?)
return am.Encapsulate(an,3,2,2,10,4,ao)
end,

Decapsulate=function(an:buffer,ao:buffer):buffer
return am.Decapsulate(an,3,2,2,10,4,ao)
end,

GenerateKeys=function():(buffer,buffer)
local an=ac.RandomBytes(32)
local ao=ac.RandomBytes(32)

return am.MLKEM_768.KeyGen(an,ao)
end,

ValidateDecapsulationKey=function(an:buffer):boolean
return am.ValidateDecapsulationKey(3,an)
end
}

am.MLKEM_1024={
KeyGen=function(an:buffer,ao:buffer):(buffer,buffer)
return am.KeyGen(4,2,an,ao)
end,

Encapsulate=function(an:buffer,ao:buffer):(buffer?,buffer?)
return am.Encapsulate(an,4,2,2,11,5,ao)
end,

Decapsulate=function(an:buffer,ao:buffer):buffer
return am.Decapsulate(an,4,2,2,11,5,ao)
end,

GenerateKeys=function():(buffer,buffer)
local an=ac.RandomBytes(32)
local ao=ac.RandomBytes(32)

return am.MLKEM_1024.KeyGen(an,ao)
end,

ValidateDecapsulationKey=function(an:buffer):boolean
return am.ValidateDecapsulationKey(4,an)
end
}

return am end function a.aw():typeof(__modImpl())local aa=a.cache.aw if not aa then aa={c=__modImpl()}a.cache.aw=aa end return aa.c end end do local function __modImpl()


local aa=table.freeze{
EdDSA=a.T(),
MlDSA=a.ag(),
MlKEM=a.aw(),
}

return aa end function a.ax():typeof(__modImpl())local aa=a.cache.ax if not aa then aa={c=__modImpl()}a.cache.ax=aa end return aa.c end end end


local aa=table.freeze{
Hashing=a.o(),
Checksums=a.r(),
Utilities=a.z(),
Encryption=a.H(),
Verification=a.ax()
}

return aa