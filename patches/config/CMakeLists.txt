# @file CMakeLists.txt
#
# purple
#
# Purple is the legal property of its developers, whose names are too numerous
# to list here.  Please refer to the COPYRIGHT file distributed with this
# source distribution.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
#
# written by SHiNE CsyFeK, 2008.05.05

PROJECT(qq)
SET(SRC_LIST buddy_info.c buddy_list.c buddy_opt.c buddy_status.c char_conv.c crypt.c file_trans.c group.c group_conv.c group_find.c group_free.c group_im.c group_info.c group_internal.c group_join.c group_network.c group_opt.c group_search.c header_info.c im.c keep_alive.c login_logout.c packet_parse.c qq.c qq_proxy.c recv_core.c send_core.c send_file.c sendqueue.c sys_msg.c udp_proxy_s5.c utils.c)

SET(GTK_TOP "D:\\GTK")
SET(PIDGIN_TOP "D:\\CODE_Test\\pidgin-2.4.0")
MESSAGE(STATUS "GTK_TOP: " ${GTK_TOP})
MESSAGE(STATUS "PIDGIN_TOP: " ${PIDGIN_TOP})

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}\\bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}\\lib)

# very IMPORTANT here!!!
LINK_DIRECTORIES(${GTK_TOP}\\lib ${PIDGIN_TOP}\\libpurple)
INCLUDE_DIRECTORIES("." ${GTK_TOP}\\include ${GTK_TOP}\\include\\glib-2.0 ${GTK_TOP}\\lib\\glib-2.0\\include ${PIDGIN_TOP}\\libpurple ${PIDGIN_TOP}\\libpurple\\win32 ${PIDGIN_TOP})
ADD_DEFINITIONS(-Wall -Waggregate-return -Wcast-align -Wdeclaration-after-statement -Werror-implicit-function-declaration -Wextra -Wno-sign-compare -Wno-unused-parameter -Winit-self -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wundef -pipe -mno-cygwin -mms-bitfields -DHAVE_CONFIG_H)
ADD_

ADD_LIBRARY(qq SHARED ${SRC_LIST})
TARGET_LINK_LIBRARIES(qq glib-2.0 ws2_32 intl purple -Wl,--enable-auto-image-base)

# executable file
#ADD_EXECUTABLE(hello SRC_LIST)

