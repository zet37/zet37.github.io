---
# layout: page
title: Compfest CTF 2024 Hacker Class [Write-up]
date : 2024-08-26 10:36:00 +0000           #YYYY-MM-DD HH:MM:SS +/-TTTT
categories : [Capture The Flag 2024, Compfest16]
tags : [ctf]
---

![Desktop View](/assets/img/ctf2024/compfest16/header/img1.png){: .center }

## Cryptography (1/4)
### reduce reuse recycle
### Pekan AES

## Forensics (4/4)
### industrialspy 2
![Desktop View](/assets/img/ctf2024/compfest16/header/ispy2.png){: .center }

Diberikan sebuah attachment **traffic.pcapng** yang berisi hasil capture-an packet data jaringan yang dapat kita analisa menggunakan `wireshark`  
![Desktop View](/assets/img/ctf2024/compfest16/chall/c_ispy2-1.png){: .center }

Jika kita lihat, seluruh isi datanya terkirim dan diterima melalui protocol **USB**, Kami mengasumsikan bahwa ini merupakan sebuah capture dari usb traffic yang kemungkinan flagnya ada pada keystroke-nya. Setelah beberapa saat googling untuk mencari tahu cara mengekstrak datanya, kami menemukan sebuah writeup yang mirip dengan chall ini <https://abawazeeer.medium.com/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4>

Untuk mengekstrak keystrokenya kita perlu mem-filter datanya terlebih dahulu, disini kami melakukannya menggunakan `tshark`
![Desktop View](/assets/img/ctf2024/compfest16/chall/c_ispy2-3.png){: .center }

> tshark -r traffic.pcapng -Y 'usb.transfer_type == 0x01 && usb.dst == "host" && !(usb.capdata == 00:00:00:00:00:00:00:00)' -T fields -e usbhid.data > usb.capdata

untuk men-convert data hex dari pcap ke huruf yang dapat dibaca kami menggunakan skrip pada writeup yang tadi dengan sedikit modifikasi.

```py
# Define the mapping of key values to descriptions
newmap = {
    4: "a", 5: "b", 6: "c", 7: "d", 8: "e", 9: "f", 10: "g", 11: "h", 12: "i",
    13: "j", 14: "k", 15: "l", 16: "m", 17: "n", 18: "o", 19: "p", 20: "q",
    21: "r", 22: "s", 23: "t", 24: "u", 25: "v", 26: "w", 27: "x", 28: "y",
    29: "z", 30: "1", 31: "2", 32: "3", 33: "4", 34: "5", 35: "6", 36: "7",
    37: "8", 38: "9", 39: "0", 40: "\n", 41: "esc", 42: "del", 43: "tab",
    44: " ", 45: "-", 46: "=", 47: "[", 48: "]", 54: ",", 55: ".", 56: "/",
    57: "CapsLock", 79: "RightArrow", 80: "LeftArrow"
}

# Define shifted characters mapping
shifted_map = {
    4: "A", 5: "B", 6: "C", 7: "D", 8: "E", 9: "F", 10: "G", 11: "H", 12: "I",
    13: "J", 14: "K", 15: "L", 16: "M", 17: "N", 18: "O", 19: "P", 20: "Q",
    21: "R", 22: "S", 23: "T", 24: "U", 25: "V", 26: "W", 27: "X", 28: "Y", 
    29: "Z", 
    #30: "!", 
    31: "@", 32: "#", 33: "$", 34: "%", 35: "^", 36: "&",37: "*", 
    #38: "(", 
    #39: ")", 
    45: "_", 46: "+", 47: "{", 48: "}", 
    #54: "<",
    #55: ">", 
    #56: "?"
}

# Open and read the hex output file
with open('usb.capdata', 'r') as myKeys:
    shift = False
    for line in myKeys:
        bytesArray = bytearray.fromhex(line.strip())
        for byte in bytesArray:
            if byte == 2:
                shift = True
            elif byte in newmap:
                if shift and byte in shifted_map:
                    print(shifted_map[byte], end='')
                else:
                    print(newmap[byte], end='')
                shift = False
            elif byte != 0:
                print(f"No map found for this value: {byte}")
```
namun hasilnya kurang konsisten terhadap huruf UPPERCASE dan lowercase karena masih ada char yang seharusnya tidak shifted namun ter-shifted.
![Desktop View](/assets/img/ctf2024/compfest16/chall/c_ispy2-5.png){: .center }

Jadi kami mencari solusi lain dan menemukan sebuah repo github dari TeamRocketIst yang memiliki skrip python untuk parsing usb keyboard stroke. <https://github.com/TeamRocketIst/ctf-usb-keyboard-parser>
![Desktop View](/assets/img/ctf2024/compfest16/chall/c_ispy2-6.png){: .center }

`tshark -r traffic.pcapng -Y 'usb.transfer_type == 0x01 && usb.dst == "host" && !(usb.capdata == 00:00:00:00:00:00:00:00)' -T fields -e usbhid.data | sed 's/../:&/g2' > usb.capdata`

Berikut script python yang digunakan
```py
#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
KEY_CODES = {
    0x04:['a', 'A'],
    0x05:['b', 'B'],
    0x06:['c', 'C'],
    0x07:['d', 'D'],
    0x08:['e', 'E'],
    0x09:['f', 'F'],
    0x0A:['g', 'G'],
    0x0B:['h', 'H'],
    0x0C:['i', 'I'],
    0x0D:['j', 'J'],
    0x0E:['k', 'K'],
    0x0F:['l', 'L'],
    0x10:['m', 'M'],
    0x11:['n', 'N'],
    0x12:['o', 'O'],
    0x13:['p', 'P'],
    0x14:['q', 'Q'],
    0x15:['r', 'R'],
    0x16:['s', 'S'],
    0x17:['t', 'T'],
    0x18:['u', 'U'],
    0x19:['v', 'V'],
    0x1A:['w', 'W'],
    0x1B:['x', 'X'],
    0x1C:['y', 'Y'],
    0x1D:['z', 'Z'],
    0x1E:['1', '!'],
    0x1F:['2', '@'],
    0x20:['3', '#'],
    0x21:['4', '$'],
    0x22:['5', '%'],
    0x23:['6', '^'],
    0x24:['7', '&'],
    0x25:['8', '*'],
    0x26:['9', '('],
    0x27:['0', ')'],
    0x28:['\n','\n'],
    0x29:['[ESC]','[ESC]'],
    0x2a:['[BACKSPACE]', '[BACKSPACE]'],
    0x2C:[' ', ' '],
    0x2D:['-', '_'],
    0x2E:['=', '+'],
    0x2F:['[', '{'],
    0x30:[']', '}'],
    0x32:['#','~'],
    0x33:[';', ':'],
    0x34:['\'', '"'],
    0x36:[',', '<'],
    0x37:['.', '>'],
    0x38:['/', '?'],
    0x39:['[CAPSLOCK]','[CAPSLOCK]'],
    0x2b:['\t','\t'],
    0x4f:[u'→',u'→'],
    0x50:[u'←',u'←'],
    0x51:[u'↓',u'↓'],
    0x52:[u'↑',u'↑']
}


#tshark -r ./usb.pcap -Y 'usb.capdata' -T fields -e usb.capdata > keyboards.txt
def read_use(file):
    with open(file, 'r') as f:
        datas = f.read().split('\n')
    datas = [d.strip() for d in datas if d] 
    cursor_x = 0
    cursor_y = 0
    offset_current_line = 0
    lines = []
    output = ''
    skip_next = False
    lines.append("")
    for data in datas:
        shift = int(data.split(':')[0], 16) # 0x2 is left shift 0x20 is right shift
        key = int(data.split(':')[2], 16)

        if skip_next:
            skip_next = False
            continue
        
        if key == 0 or int(data.split(':')[3], 16) > 0:
            continue
        
        if shift != 0:
            shift=1
            skip_next = True
        
        if KEY_CODES[key][shift] == u'↑':
            lines[cursor_y] += output
            output = ''
            cursor_y -= 1
        elif KEY_CODES[key][shift] == u'↓':
            lines[cursor_y] += output
            output = ''
            cursor_y += 1
        elif KEY_CODES[key][shift] == u'→':
            cursor_x += 1
        elif KEY_CODES[key][shift] == u'←':
            cursor_x -= 1
        elif KEY_CODES[key][shift] == '\n':
            lines.append("")
            lines[cursor_y] += output
            cursor_x = 0
            cursor_y += 1
            output = ''
        elif KEY_CODES[key][shift] == '[BACKSPACE]':
            output = output[:-1]
            #lines[cursor_y] = output
            cursor_x -= 1
        else:
            output += KEY_CODES[key][shift]
            #lines[cursor_y] = output
            cursor_x += 1
    #print(lines)
    if lines == [""]:
        lines[0] = output
    if output != '' and output not in lines:
        lines[cursor_y] += output
    return '\n'.join(lines)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Missing file to read...')
        exit(-1)
    sys.stdout.write(read_use(sys.argv[1]))
```

![Desktop View](/assets/img/ctf2024/compfest16/chall/c_ispy2-7.png){: .center }

> **Flag: COMPFEST16{L0Ve_m3_s0me_USB_f0rens1CS_fd746ec8b3}**

Reference:
1. <https://abawazeeer.medium.com/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4>
2. <https://steemit.com/reverseengineering/@nileshevrywhr/auth0-ctf-reverse-engineering-usb-keystrokes-from-pcaps>
3. <https://github.com/TeamRocketIst/ctf-usb-keyboard-parser>
4. <https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf>


### Color pallete
![Desktop View](/assets/img/ctf2024/compfest16/header/cp1.png){: .center }

Jika kita lihat deskripsi dari chall ini terdapat kalimat `dominance in art` dan `choose 5 color to put into their color pallete` jadi kita perlu mendapatkan 5 warna yang paling dominan pada gambar yang diberikan 

![Desktop View](/assets/img/ctf2024/compfest16/chall/coming_soon_colorfest.png){: .center }

Saya mencoba untuk mengambil hex color dari gambar tersebut menggunakan script python yang saya buat

```python
from PIL import Image
from collections import Counter

def get_top_dominant_colors(image_path, top_n=6):
    # Open the image
    img = Image.open(image_path)
    # img = img.resize((100, 100))  # Resize for faster processing
    img = img.convert('RGB')  # Convert to RGB mode
    
    # Get colors and their frequencies
    pixels = list(img.getdata())
    counter = Counter(pixels)
    
    # Get the top n most common colors
    most_common_colors = counter.most_common(top_n)
    
    # Convert the RGB values to hex
    hex_colors = ['#{:02x}{:02x}{:02x}'.format(color[0], color[1], color[2]) for color, _ in most_common_colors]
    
    return hex_colors

image_path = 'coming_soon_colorfest.png'
top_colors = get_top_dominant_colors(image_path, top_n=6)
# print("The top 10 dominant colors are:")
for i, color in enumerate(top_colors, 1):
    # print(f"{i}: {color}")
    print(color)
```

Didapatkan hex colornya yaitu
![Desktop View](/assets/img/ctf2024/compfest16/chall/cp1.png){: .center }

- #ffffff (ini hex color dari warna putih)
- #b6bbb7
- #734974
- #aec8a7
- #b35777
- #cb4bae

Dengan men-exclude hex color dari warna putih dan men-concat seluruh hex colornya dan menghapus simbol # di setial awal hex kita dapatkan nilai hexnya yaitu `b6bbb7734974aec8a7b35777cb4bae`

Untuk mendapatkan flagnya kita perlu men-encode hexnya ke base64
![Desktop View](/assets/img/ctf2024/compfest16/chall/cp3.png){: .center }

> **Flag: COMPFEST16{tru3c0l0rsins1d3y0uu}**

Tools:
1. <https://imagecolorpicker.com/>
2. <https://cyberchef.io/>

### Evil_Jarkom
![Desktop View](/assets/img/ctf2024/compfest16/header/evil_jarkom1.png){: .center }

Diberikan sebuah attachment traffic.pcapng, kita dapat menganalisanya dengan tools `wireshark`
![Desktop View](/assets/img/ctf2024/compfest16/chall/evil1.png){: .center }

chall ini merupakan sebuah representasi dari kerentanan evil bit pada RFC 3514, berikut penjelasannya
- <https://blog.benjojo.co.uk/post/evil-bit-RFC3514-real-world-usage>
- <https://ctftime.org/writeup/36170>

Untuk mendapatkan flagnya kita hanya perlu memfilter flags ipnya yang memiliki resesrved bit
![Desktop View](/assets/img/ctf2024/compfest16/chall/evil2.png){: .center }

Saya menggunakan tools `tshark` untuk mengekstrak data hexnya dan me-pipenya dengan `xxd` untuk mengubahnya menjadi ascii
![Desktop View](/assets/img/ctf2024/compfest16/chall/evil3.png){: .center }

> **Flag: COMPFEST16{rfc_3514_security_bit_145eef449d}**

### Bames_Jond_Investigation Team
![Desktop View](/assets/img/ctf2024/compfest16/header/bond.png){: .center }

Chall ini sedikit tricky karena kita harus menjawab pertanyaan dari soal lalu jawabannya dijadikan sebuah flag, perbedaan huruf kecil, huruf kapital dan urutannya juga berpengaruh, mungkin ini menjadi alasan mengapa yang berhasil solve soal ini hanya 12 tim.

Pertanyaan soal
1. The operating system that the machine runs.
Write in [OperatingSystem]-[Version]. For example, Windows-7 or Ubuntu-20.07
2. Application(s) that is currently opened by the user excluding file explorer.
Write in [ApplicationOne]-[ApplicationTwo]. For example, MicrosoftPowerPoint-MicrosoftWord-Notepad.
3. File/folder(s) that is contained inside "Tugas Sekolah" folder.
Write in in their original name without their extension in this format, [File/Folder 1]-[File/Folder 2]. For example, Important Folder-Melon Cat
4. Programming language that the user are using inside that machine. Write in [Language1]-[Language2]. For example, C-C++-Java

Kita diberikan sebuah link google drive yang yang isinya adalah file dengan format .mem
- <https://drive.google.com/file/d/181HJuIx_nEF-CSLcf6P3sxCWrW3MmtD8/view>

Kita bisa menganalisa mengakses file memory tersebut menggunakan tools `volatility` pada linux, dimulai dengan command imageinfo untuk mendapatkan profile summary

- Jawaban pertanyaan 1  
![Desktop View](/assets/img/ctf2024/compfest16/chall/james1.png){: .center }
Jawaban: **Windows-7**

- Jawaban pertanyaan 2  
Untuk soal nomor 2 kita dapat melihat aplikasi yang running menggunakan command pslist ataupun pstree
![Desktop View](/assets/img/ctf2024/compfest16/chall/james2.png){: .center }
![Desktop View](/assets/img/ctf2024/compfest16/chall/james3.png){: .center }

Karena disitu terdapat process mspaint.exe saya coba untuk mendump processnya untuk memastikan aplikasi yang saat itu dibuka.
![Desktop View](/assets/img/ctf2024/compfest16/chall/james4.png){: .center }

Untuk membaca dan mengakses file dumpnya kita bisa mengubah nama filenya menjadi format .data dan mengaksesnya menggunakan `gimp`
![Desktop View](/assets/img/ctf2024/compfest16/chall/james6.png){: .center }
![Desktop View](/assets/img/ctf2024/compfest16/chall/james7.png){: .center }

Setelah dicari width dan offset yang pas untuk mendapatkan gambar yang jelas, saya mendapatkannya di angka
- offset = 141229348
- width = 2133

![Desktop View](/assets/img/ctf2024/compfest16/chall/james8.png){: .center }
Terlihat aplikasi yang dibuka kecuali ramcapturer dan file explorer adalah
1. Microsoft Edge
2. Microsoft Paint
3. Windows Media Player

Jawaban: **MicrosoftEdge-MicrosoftPaint-WindowsMediaPlayer**

- Jawaban pertanyaan 3  
Kita bisa menggunakan command filescan ataupun strings untuk menemukan folder dan file yang ada pada memory tersebut.
![Desktop View](/assets/img/ctf2024/compfest16/chall/james9.png){: .center }

Jawaban: **Definetly Tugas Sekolah**

- Jawaban pertanyaan 4  
Untuk mengetahui programming language yang ada pada merory tersebut kita dapat memanfaatkan command envars untuk melihat PATH environment variables pada memory tersebut.
![Desktop View](/assets/img/ctf2024/compfest16/chall/james10.png){: .center }
![Desktop View](/assets/img/ctf2024/compfest16/chall/james11.png){: .center }

Dari informasi tersebut kita dapat mengetahui ada Python dan Java pada PATH

Jawaban: **Java-Python**

 **Flag: COMPFEST16{Windows-7_MicrosoftEdge-MicrosoftPaint-WindowsMediaPlayer_Definetly Tugas Sekolah_Java-Python}**


## Misc (2/4)
### echooo
### Pybidden

## Reverse Engineering (1/4)
### Serial Key
### Random

## Web Exploitation (2/4)
### magik
### pink

