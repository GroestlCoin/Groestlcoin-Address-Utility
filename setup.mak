#	Build MSI packages

WIX_LINK = light.exe -ext WixUIExtension -ext WixUtilExtension -dWixUILicenseRtf=doc\gplv3.rtf

msi : groestlcoin-address-utility.msi

bin\Release\groestlcoin-address-utility.exe :
	msbuild GrsAddress.sln /p:Configuration=Release,Platform=x86

groestlcoin-address-utility.msi : groestlcoin-address-utility.wxs bin\Release\groestlcoin-address-utility.exe
	candle.exe -o groestlcoin-address-utility.wixobj groestlcoin-address-utility.wxs
	$(WIX_LINK)  -out $@ groestlcoin-address-utility.wixobj

