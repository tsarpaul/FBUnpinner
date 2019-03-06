# FBUnpinner

SUPPORTS TLS1.3 for x86
TODO: ARM TLS1.3 support

A script to automate removing certificate pinning defense from Facebook applications.

TESTED FOR THE FOLLOWING APPS:
- com.facebook.katana (Facebook for Android)
- com.facebook.orca (Messenger)
- com.facebook.lasso (Lasso)

### How-to
##### [REQUIRES ROOT]

1. Make sure you have run the desired Facebook application atleast once - what happens is that the cert pinning library (libcoldstart.so) is unpacked from an archive embedded in the APK.

2. Get root shell in your device:
```
$(comp): adb shell
$(phone): su
```

3. Pull libcoldstart.so from your desired Facebook application:
```
#(phone): cp /data/data/com.facebook.katana/lib-xzs/libcoldstart.so /sdcard/libcoldstart.so
#(phone): exit
$(phone): exit
$(comp): adb pull /sdcard/libcoldstart.so FBUnpinner/
```

4. Patch the file:
```
$ python3 patch.py
```

5. Replace libcoldstart.so in the phone with the patched version:
```
$(comp): adb push libcoldstart-patched.so /sdcard/libcoldstart.so
$(comp): adb shell
$(phone): su
#(phone): cp /sdcard/libcoldstart.so /data/data/com.facebook.katana/lib-xzs/libcoldstart.so
#(phone): chmod 777 /data/data/com.facebook.katana/lib-xzs/libcoldstart.so
```

### TODO
A script to just patch an APK

### Reference
https://serializethoughts.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/
