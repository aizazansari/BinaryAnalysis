from PIL import Image
import numpy as np

img1 = Image.open("/Users/deebthik/Desktop/blaaaaaaaa.png")

l = []

for y in range(img1.height):
  for x in range(img1.width):
    pixel = img1.getpixel((x, y))
    l += [pixel]

print (l)
