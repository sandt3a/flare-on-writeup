[TOC]

# flare-on 2015

> password = 'flare'
>
> 解出的 flag 请包裹上 `flag{}` 后提交，例如你解出的答案是 `hello@flare-on.com`，你应该提交 `flag{hello@flare-on.com}`。

## challenge 1

input -> xor 0x7D -> compare

> bunny_sl0pe@flare-on.com

## challenge 2



![image-20251215200751396](C:\Users\lyxin65\AppData\Roaming\Typora\typora-user-images\image-20251215200751396.png)

需要分析汇编

- `sahf`会把`CF`(进位标志位) 设为1, 与后面的`adc`联动, 额外加上进位
- `lodsb`是从`SI`读一位字符
- `pushf`和`popf`会保存寄存器, 也就是前面设为1的`CF`后面要用
- `scasb`是比较然后寄存器自增, 详情:
  - `SCASB` 执行以下操作：
    - 比较 `AL` 寄存器与 `[EDI]` 或 `[RDI]` 指向的内存字节
    - 根据比较结果设置标志位（ZF、SF、CF 等）
    - 自动更新索引寄存器：
      - **16位模式**：`DI = DI ± 1`
      - **32位模式**：`EDI = EDI ± 4`
      - **64位模式**：`RDI = RDI ± 1`
      - 方向由 `DF` 标志决定：`DF=0` 递增，`DF=1` 递减
- `xchg` -> exchange
- `cmovnz` -> **c**onditional **mov** if **n**on **z**ero

一些注意点 ：

- enc被IDA错误识别为 _start 后面的指令了, 实际的 _start 只有一个 call
- enc在传入的时候识别错误, 可以动调找到, 暂时不清楚怎么静态分析

```python
from z3 import *

def rol(value, shift, bits=32):
    return ((value << shift) & ((1 << bits) - 1)) | (value >> (bits - shift))

enc = [0xAF,0xAA,0xAD,0xEB,0xAE,0xAA,0xEC,0xA4,0xBA,0xAF,0xAE,0xAA,0x8A,0xC0,0xA7,0xB0,0xBC,0x9A,0xBA,0xA5,0xA5,0xBA,0xAF,0xB8,0x9D,0xB8,0xF9,0xAE,0x9D,0xAB,0xB4,0xBC,0xB6,0xB3,0x90,0x9A,0xA8]

L = 37
solver = Solver()

x = [BitVec(f'x_{i}', 8) for i in range(L)]

v4 = 0
for i in range(37):
    v10 = 0x1C7 ^ x[i]
    v12 = (rol(1, v4 & 3) + 1 + v10) & 0xff
    v4 += v12
    solver.add(enc[L - i - 1] == v12)

solver.check()
m = solver.model()
print(''.join(chr(m[xi].as_long()) for xi in x))
```

> a_Little_b1t_harder_plez@flare-on.com

## challenge 3

use pyinstxtractor.py to unpack -> elfie.pyc -> decompile failure

look into elfie.pyc will find it looks like

![image-20251215221429206](C:\Users\lyxin65\AppData\Roaming\Typora\typora-user-images\image-20251215221429206.png)

replace exec with print will get the source code, though obfuscated

```python
b"from PySide import QtGui, QtCore\nimport base64\nOOO00O00OO0OO000OOOO00000000OOO0 = ''.join((OOOO00OO0OOO000OOOO00O00O0OOOOOO for OOOO00OO0OOO000OOOO00O00O0OOOOOO in reversed('...')))\nclass OO00O0O00OOO00OOOO0O00O0000OOOOO(getattr(QtGui, 'tidEtxeTQ'[::-1])):\n    def __init__(self, OO0O0O0O0OO0OO00000OO00O0O0000O0, OO00O00O00OO00OO0OO0OO000O0O00OO, OO0OOO00O00O0OO00000OO0000OO0OOO):\n        super(OO00O0O00OOO00OOOO0O00O0000OOOOO, self).__init__(OO0O0O0O0OO0OO00000OO00O0O0000O0)\n        self.OO0O0O0O0OO0OO00000OO00O0O0000O0 = OO0O0O0O0OO0OO00000OO00O0O0000O0\n        self.OO00O00O00OO00OO0OO0OO000O0O00OO = OO00O00O00OO00OO0OO0OO000O0O00OO\n        self.OO0OOO00O00O0OO00000OO0000OO0OOO = OO0OOO00O00O0OO00000OO0000OO0OOO\n        self.OOOOOOOOOO0O0OOOOO000OO000OO0O00 = False\n\n    def O000OOOOOO0OOOO00000OO0O0O000OO0(self):\n        O0O0O0000OOO000O00000OOO000OO000 = getattr(self, 'txeTnialPot'[::-1])()\n        if (O0O0O0000OOO000O00000OOO000OO000 == ''.join((OO00O00OOOO00OO000O00OO0OOOO0000 for OO00O00OOOO00OO000O00OO0OOOO0000 in reversed('moc.no-eralf@OOOOY.sev0000L.eiflE')))):\n                self.OO0O0O0O0OO0OO00000OO00O0O0000O0.setWindowTitle('!sseccus taerg'[::-1])\n                self.OOOOOOOOOO0O0OOOOO000OO000OO0O00 = True\n                self.OO0O0O0O0OO0OO00000OO00O0O0000O0.setVisible(False)\n                self.OO0O0O0O0OO0OO00000OO00O0O0000O0.setVisible(True)\n\n    def keyPressEvent(self, OO000O0O0OOOOOO0OO0OO00O0OOO00OO):\n        if ((OO000O0O0OOOOOO0OO0OO00O0OOO00OO.key() == getattr(QtCore, 'tQ'[::-1]).Key_Enter) or (OO000O0O0OOOOOO0OO0OO00O0OOO00OO.key() == getattr(QtCore, 'tQ'[::-1]).Key_Return)):\n            self.O000OOOOOO0OOOO00000OO0O0O000OO0()\n        else:\n            super(OO00O0O00OOO00OOOO0O00O0000OOOOO, self).keyPressEvent(OO000O0O0OOOOOO0OO0OO00O0OOO00OO)\n\n    def paintEvent(self, OO000O0O0OOOOOO0OO0OO00O0OOO00OO):\n        OOOOOOOOOO00O00O0OO0OO00OOO0OOO0 = getattr(self, 'tropweiv'[::-1])()\n        O000OOO000O0OO00O00OO0O00O0O00O0 = getattr(QtGui, 'retniaPQ'[::-1])(OOOOOOOOOO00O00O0OO0OO00OOO0OOO0)\n        if self.OOOOOOOOOO0O0OOOOO000OO000OO0O00:\n            getattr(O000OOO000O0OO00O00OO0O00O0O00O0, 'pamxiPward'[::-1])(getattr(self, 'tcer'[::-1])(), self.OO0OOO00O00O0OO00000OO0000OO0OOO)\n        else:\n            getattr(O000OOO000O0OO00O00OO0O00O0O00O0, 'pamxiPward'[::-1])(getattr(self, 'tcer'[::-1])(), self.OO00O00O00OO00OO0OO0OO000O0O00OO)\n        super(OO00O0O00OOO00OOOO0O00O0000OOOOO, self).paintEvent(OO000O0O0OOOOOO0OO0OO00O0OOO00OO)\nOOO00O000O0000OO000OO0000O000000 = getattr(QtGui, 'noitacilppAQ'[::-1])(['000000000000000000000000'[::-1]])\nOO0000OOOOO000000OO0OOO00OO00OOO = getattr(QtGui, 'wodniWniaMQ'[::-1])()\nOO00O00O00OO00OO0OO0OO000O0O00OO = getattr(QtGui, 'pamxiPQ'[::-1])()\ngetattr(OO00O00O00OO00OO0OO0OO000O0O00OO, 'ataDmorFdaol'[::-1])(getattr(base64, 'edoced46b'[::-1])(OOO00O00OO0OO000OOOO00000000OOO0))\nOO0OOO00O00O0OO00000OO0000OO0OOO = getattr(QtGui, 'pamxiPQ'[::-1])()\ngetattr(OO0OOO00O00O0OO00000OO0000OO0OOO, 'ataDmorFdaol'[::-1])(getattr(base64, 'edoced46b'[::-1])(OO0O00000OO0O0O0OOOO0OO0OOO000O0))\nOO00OOOOOO0000000OOO0O000OO0O0OO = getattr(OO00O00O00OO00OO0OO0OO000O0O00OO, 'htdiw'[::-1])()\nO000OO0O00O00O00O0OOOOOO00O000OO = getattr(OO00O00O00OO00OO0OO0OO000O0O00OO, 'thgieh'[::-1])()\ngetattr(OO0000OOOOO000000OO0OOO00OO00OOO, 'eltiTwodniWtes'[::-1])('!ereht eno dnif nac uoy !edisni kooL'[::-1])\ngetattr(OO0000OOOOO000000OO0OOO00OO00OOO, 'eziSdexiFtes'[::-1])(OO00OOOOOO0000000OOO0O000OO0O0OO, O000OO0O00O00O00O0OOOOOO00O000OO)\nOO000O0OO0000000OO0OO0O0000O0O00 = OO00O0O00OOO00OOOO0O00O0000OOOOO(OO0000OOOOO000000OO0OOO00OO00OOO, OO00O00O00OO00OO0OO0OO000O0O00OO, OO0OOO00O00O0OO00000OO0000OO0OOO)\ngetattr(OO0000OOOOO000000OO0OOO00OO00OOO, 'tegdiWlartneCtes'[::-1])(OO000O0OO0000000OO0OO0O0000O0O00)\ngetattr(OO0000OOOOO000000OO0OOO00OO00OOO, 'wohs'[::-1])()\ngetattr(OOO00O000O0000OO000OO0000O000000, '_cexe'[::-1])()\n\n"
```

observe lead the way to `reversed('moc.no-eralf@OOOOY.sev0000L.eiflE')`, which is the flag

It's in 2025, so we can just feed deepseek with the code above, which gives us:

```python
from PySide import QtGui, QtCore
import base64

# This contains base64 data (truncated as '...' in the provided code)
base64_data_1 = ''.join((char for char in reversed('...')))

class CustomTextField(QtGui.QLineEdit):
    def __init__(self, parent, normal_pixmap, success_pixmap):
        super(CustomTextField, self).__init__(parent)
        self.parent = parent
        self.normal_pixmap = normal_pixmap
        self.success_pixmap = success_pixmap
        self.is_success = False

    def check_password(self):
        text = self.text()
        # The password is "Elfie.L0000es@YOU@flare-on.com" (reversed)
        if text == ''.join((char for char in reversed('moc.no-eralf@OOOOY.sev0000L.eiflE'))):
            self.parent.setWindowTitle('Great success!'[::-1])
            self.is_success = True
            # These two lines contradict each other - likely obfuscation
            self.parent.setVisible(False)
            self.parent.setVisible(True)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Enter or event.key() == QtCore.Qt.Key_Return:
            self.check_password()
        else:
            super(CustomTextField, self).keyPressEvent(event)

    def paintEvent(self, event):
        viewport = self.viewport()
        painter = QtGui.QPainter(viewport)
        if self.is_success:
            painter.drawPixmap(self.rect(), self.success_pixmap)
        else:
            painter.drawPixmap(self.rect(), self.normal_pixmap)
        super(CustomTextField, self).paintEvent(event)

# Create application
app = QtGui.QApplication([])

# Create main window
window = QtGui.QMainWindow()

# Create first pixmap and load from base64
normal_pixmap = QtGui.QPixmap()
normal_pixmap.loadFromData(base64.b64decode(base64_data_1))

# Create second pixmap (note: OO0O00000OO0O0O0OOOO0OO0OOO000O0 is not defined in provided code)
# This would cause an error unless it's defined elsewhere
success_pixmap = QtGui.QPixmap()
success_pixmap.loadFromData(base64.b64decode(OO0O00000OO0O0O0OOOO0OO0OOO000O0))

# Get dimensions from normal pixmap
width = normal_pixmap.width()
height = normal_pixmap.height()

# Set window properties
window.setWindowTitle('Look inside! you can find one there!'[::-1])
window.setFixedSize(width, height)

# Create custom text field
text_field = CustomTextField(window, normal_pixmap, success_pixmap)
window.setCentralWidget(text_field)

# Show window and run application
window.show()
app.exec_()
```

note ` if text == ''.join((char for char in reversed('moc.no-eralf@OOOOY.sev0000L.eiflE'))):` also gives the flag.

> Elfie.L0000ves.YOOOO@flare-on.com

## challenge 4

>  Beautiful problem

### key point

- program will modify the data before main, which is correct

![image-20251217145121531](C:\Users\lyxin65\AppData\Roaming\Typora\typora-user-images\image-20251217145121531.png)

- however, upx -d will not load the program, and the code above will never run

a simple way is to modify the binary manually

or you can dynamic debugging to find the true OEP and dump memory, but my dumpfile could not run correctly (maybe because the section name is still upx0 and upx1)



the main logic is

get current hour -> calculate MD5 hash -> diff with base64_decode(vec[hour]) -> xor with another base64_decode(enc[hour])

![5c2dbcd3701924515eca980722703f88](D:\SOFTWARE\tencent\shit\Tencent Files\3061496286\nt_qq\nt_data\Pic\2025-12\Ori\5c2dbcd3701924515eca980722703f88.png)

```python
import base64

hours = [b'K7IfRF4nOiNn9Jsqt9wFCq==',
b'vAvack0BPyMQiq0MkChFqq==',
b'NMImwkviE46VACNHafRqVW==',
b'HMzOnqAQZzalVvP0Re7FAa==',
b'7h9+E7q3qS6gGux3htE1pa==',
b'I7BbEdHKp5ArZgPn5Suxcq==',
b'bUYHTdFhKeZdZMvgYbebea==',
b'IEDozaUmrIv6kD4gfNLnxq==',
b'4RQqw/mg9g+SOIptYYdIZW==',
b'xNmQghI+i0lB/V9F48PAOW==',
b'AlmP2PIt40czX9ITxlNjqa==',
b'e8J/2xCbnWoNaC+oeD6Szq==',
b'wmIvyVwp0NB1KKiaAnUmcq==',
b'3lM+l2boxFKD65zzVTr0Jq==',
b'tE2YjaOEdWonZCIZ3PiMta==',
b'2dHPhL1k0gH5YNiuqUId1a==',
b'AZg9+N+B/S4Mm4h/QrVwQq==',
b'r+1Zo40qVIjEZRO0tvm1HG==',
b'QerwgAVqJZUG6/YZeyp3+q==',
b'/+uDpN2cLYn1Ihbo7DXQSG==',
b'fFqAlPA640hD5iw7dNJ0Hq==',
b'9AFKD80WqRsAKixwiWFnka==',
b'V21SGz7jDBbdRSucfNW9fq==',
b'Hp8u+Kw+pkrZNNWcDXELqq==']
encs = [b'XTd3NiPLZBQ5N1FqkBN+a/Av6SpqBS/K',
b'am0YoDLZYlREsg5Mt62+mZcil2AdEmRK',
b'YWd+ADeGfR3BakQHzJAXZFTf4ZAlkXtJ',
b'0W4AbhlcOkn/1dK0YIk+gUnlb1SOYAl9',
b'UrCmsSbFl/3Y6cA3E1VutOLserwAvc2J',
b'3T6ZsuWmuQxLPqKnGkL2E+6BRHywb1d7',
b'u4ttHuoV/x+3PWygRN1GyMpbZTOzPp8H',
b'3i88vx/KkXyoql1gCbuSl+ZkiqOL7YLi',
b'T9lIAODUMvZyY0ctRuYdVyEx/ZxDzzSc',
b'cXTykqZwtNgVL5WFHAy70tTErxzw3uWV',
b'pDTB6+Z7JNpTRRVToTwOmG2ErRs28iWT',
b'rQcn6anPwJdtAkZoD7lnf3BLKlDzyLHU',
b'dAdNu4hNV0wb+YfadRFTEZ3L+GZB7l0B',
b'IDhmhHqMmmPPGVuz2lGv/7Mu0ufoltku',
b'gixafx52yJd5PkVZUp5hpIJa3uOKFwbU',
b'JvaBlYKIVvSnOXfujitIPR0vbNbZkB8f',
b'pLNpYWVZK/1swUk/Z3E32W4C0Prr+jgJ',
b'eOubcVL40XeQP9L0kZ9u9clahfwJC9fp',
b'/sWKkn+44GJuGP/ZD++wI81PoxEfS+bw',
b'QO1VdWNQ+Hab4rmoI7alWjRiCLbt4FHo',
b'qjXOh+lsJNkPJEB7Absv93dzDuc42yWS',
b'Om+wrRLyl4FU+EAwrwUSwPckIXNJuY3z',
b'6GuESoQHgim3X6zcCbbCz9Paa++WQHRD',
b'0zDMYZhwuzCh9X9cexVem+hsE5rR3vpj']

for i in range(24):
    hour = hours[i].swapcase();
    enc = encs[i].swapcase()
    hour = base64.b64decode(hour)
    enc = base64.b64decode(enc)
    result = ""
    for x in range(len(enc)):
        result += chr(hour[x % len(hour)] ^ enc[x])

    print(result)
```

> Uhr1thm3tic@flare-on.com

#### challenge 5

relatively easy problem

key was moded by adding `flarebearstare` in cycle

only to notice the base64 table is `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/`

![image-20251217161835711](C:\Users\lyxin65\AppData\Roaming\Typora\typora-user-images\image-20251217161835711.png)

use hand (maybe there are better method?) and wireshark to extract data transfered (4-digit each POST pack)

```python
import base64

ss = b'flarebearstare'
enc = b'UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW=='
key = bytearray(base64.b64decode(enc.swapcase()))

for i in range(len(key)):
    key[i] -= ss[i % 14]
print(key)
```

> Sp1cy_7_layer_OSI_dip@flare-on.com

OK there is better way to process PCAP file, using scapy (http://www.secdev.org/projects/scapy/)

```python
import sys
from scapy.all import *
if __name__ == '__main__':
    pkts = rdpcap(sys.argv[1])

    key = ""
    for pkt in pkts:
        if TCP in pkt and Raw in pkt and 'KEY' in pkt[Raw].load:
            headers, body = pkt[Raw].load.split("\r\n\r\n",1)
            key += body

    print("[+] KEY: %s" % key)
```





#### challenge 6

the Java just pass the input string to libvalidate.so

In function `Java_com_flareon_flare_ValidateActivity_validate`,  every two bytes of input string was used to form a number and calculate the prime-factorization
then diff with 0xd94 of enc data, and the length have to be 23.

we can extract the data and caculate the flag using some tool like ExportPlus of IDA.
I tried to write a pyGhidra script but failed. I don't know why my gridra seems doesn't support python.

the exp is in ![here](./chal6_solver.py)

> 

#### challenge 7

> 

#### challenge 8

#### challenge 9

#### challenge 10

> 

#### challenge 11