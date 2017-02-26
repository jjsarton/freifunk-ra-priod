include $(TOPDIR)/rules.mk

PKG_NAME:=ra-priod
PKG_RELEASE:=1

PKG_MAINTAINER:=Jean-Jacques Sarton <jj@jjsarton.de>
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/ra-priod
  SECTION:=base
  CATEGORY:=Base system
  DEPENDS:=+gluon-core +kmod-ipt-nfqueue +libnetfilter-queue +kmod-ipt-extra +iptables-mod-nfqueue
  TITLE:=RA set priority
endef

TARGET_CPPFLAGS := \
	-D_GNU_SOURCE \
	-I$(STAGING_DIR)/usr/include \
	-I$(PKG_BUILD_DIR) \
	$(TARGET_CPPFLAGS) \
	-I$(LINUX_DIR)/user_headers/include

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		LIBS="$(TARGET_LDFLAGS) -lnetfilter_queue -lnfnetlink -lmnl"
endef

define Package/ra-priod/install
	$(CP) ./files/* $(1)/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ra-priod $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,ra-priod))

