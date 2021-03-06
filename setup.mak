#	Build MSI packages

WIX_LINK = light.exe -ext WixUIExtension -ext WixUtilExtension -dWixUILicenseRtf=doc\gplv3.rtf

all : zip msi

zip : groestlcoin-address-utility.zip

msi : groestlcoin-address-utility.msi

bin\Release\GrsAddress.exe :
	msbuild GrsAddress.sln /p:Configuration=Release,Platform=x86


groestlcoin-address-utility.zip : bin\Release\GrsAddress.exe
	-rm $@
	copy bin\Release\GrsAddress.exe .
	7z a $@ -tzip GrsAddress.exe ThoughtWorks.QRCode.dll BouncyCastle.Crypto.dll groestlcoin-note.png

groestlcoin-address-utility.msi : groestlcoin-address-utility.wxs bin\Release\GrsAddress.exe
	candle.exe -o groestlcoin-address-utility.wixobj groestlcoin-address-utility.wxs
	$(WIX_LINK)  -out $@ groestlcoin-address-utility.wixobj

