/*
	Copyright (C) 2004-2005 Cory Nelson

	This software is provided 'as-is', without any express or implied
	warranty.  In no event will the authors be held liable for any damages
	arising from the use of this software.

	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:

	1. The origin of this software must not be misrepresented; you must not
		claim that you wrote the original software. If you use this software
		in a product, an acknowledgment in the product documentation would be
		appreciated but is not required.
	2. Altered source versions must be plainly marked as such, and must not be
		misrepresented as being the original software.
	3. This notice may not be removed or altered from any source distribution.
	
	CVS Info :
		$Author: phrostbyte $
		$Date: 2005/02/26 05:14:20 $
		$Revision: 1.2 $
*/

#pragma once

#include <set>

#define LOCALIP_ADAPTER		1
#define LOCALIP_GATEWAY		2
#define LOCALIP_DHCP			4
#define LOCALIP_DNS			8
void GetLocalIps(std::set<unsigned int> &ips, unsigned int types);
