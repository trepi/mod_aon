mod_aon.la: mod_aon.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_aon.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_aon.la
