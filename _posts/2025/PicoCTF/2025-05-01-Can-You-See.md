---
title: "PicoCTF - CanYouSee Writeup"
date: 2025-05-01
categories: [CTF, picoCTF]
image: /assets/2025/PicoCTF/logo-picoctf.jpg
alt: "picoCTF wallpaper"
---

In the "CanYouSee?" CTF challenge, I was given an image and asked to find a hidden flag. At first, the image didn’t show anything unusual, but by carefully examining the file, I was able to uncover a hidden clue. Here's how I solved it step by step:

![CanYouSee](/assets/2025/PicoCTF/CanYouSee/1.png)  

### Step 1: Download and Open the Image
I started by downloading the image file. When I opened it, there was nothing obviously suspicious or hidden in the picture itself. This made me think that the flag might be hidden somewhere else, like in the file's metadata or structure.

![CanYouSee](/assets/2025/PicoCTF/CanYouSee/2.png)  

### Step 2: Check the File Type
To make sure the image was just an image and not something else, I used a command called `file` to check the type of file. It confirmed that the file was indeed an image. This was helpful because it told me that the image was probably not trying to trick me by being disguised as another type of file.

```bash
file ukn_reality.jpg
ukn_reality.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 4308x2875, components 3
```

### Step 3: Inspect the Metadata with ExifTool
Next, I decided to check the image’s metadata. Metadata is extra information about a file, like when it was created or what camera was used to take a picture. Sometimes, CTF challenges hide clues in this metadata.

I used a tool called `ExifTool` to read the metadata of the image. This is when I found something interesting: there was a field called "Attribution URL." It looked like it might contain some important information. When I looked closer, I saw that part of the URL seemed to be encoded in a format called Base64.

```bash
exiftool ukn_reality.jpg
ExifTool Version Number         : 13.10
File Name                       : ukn_reality.jpg
Directory                       : .
File Size                       : 2.3 MB
File Modification Date/Time     : 2024:03:12 01:05:57+01:00
File Access Date/Time           : 2025:05:01 18:57:13+02:00
File Inode Change Date/Time     : 2025:05:01 18:56:58+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
XMP Toolkit                     : Image::ExifTool 11.88
Attribution URL                 : cGljb0NURntNRTc0RDQ3QV9ISUREM05fZDhjMzgxZmR9Cg==
Image Width                     : 4308
Image Height                    : 2875
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 4308x2875
Megapixels                      : 12.4
```

### Step 4: Decode the Base64 String
Base64 is a way to encode text to make it look like random characters. I copied the encoded part from the URL and pasted it into an online Base64 decoder. After decoding, the result was a readable message.

![CanYouSee](/assets/2025/PicoCTF/CanYouSee/3.png)  
