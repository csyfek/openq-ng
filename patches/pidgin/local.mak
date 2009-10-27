GTK_TOP := D:/GTK
LIBXML2_TOP := $(GTK_TOP)
CFLAGS += `pkg-config --cflags libxml-2.0`
