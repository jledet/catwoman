/*
 * Copyright (C) 2007 B.A.T.M.A.N. contributors:
 * Marek Lindner
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */





#include "batman-adv-core.h"
#include "net80211/ieee80211_batman.h"


int batman_attach_net80211(struct net_device *dev, u_int8_t *ie_buff, u_int8_t *ie_buff_len);
int batman_detach_net80211(struct net_device *dev);


struct batman_ops_net80211 bops_net80211 = {
	.attach = batman_attach_net80211,
	.detach = batman_detach_net80211,
};



int init_module(void)
{
	batman_ops_net80211 = &bops_net80211;
	return 0;
}

void cleanup_module(void)
{
	batman_ops_net80211 = NULL;
}



int batman_attach_net80211(struct net_device *dev, u_int8_t *ie_buff, u_int8_t *ie_buff_len)
{
	int retval;

	retval = batman_attach(dev, ie_buff, ie_buff_len);

	if (retval == 0) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
		MOD_INC_USE_COUNT;
#else
		try_module_get(THIS_MODULE);
#endif

	}

	/* retval 1 indicates that the interface is already attached */
	if (retval == 1)
		retval = 0;

	return retval;
}

int batman_detach_net80211(struct net_device *dev)
{
	int retval;

	retval = batman_detach(dev);

	if (retval == 0) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
		MOD_DEC_USE_COUNT;
#else
		module_put(THIS_MODULE);
#endif

	}

	/* retval 1 indicates that the interface has not been attached yet */
	if (retval == 1)
		retval = 0;

	return retval;
}



MODULE_LICENSE("GPL");

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);