# FBUnpinner

A script to automate removing certificate pinning defense from Facebook applications.

TESTED FOR THE FOLLOWING APPS:
- com.facebook.katana (Facebook for Android)
- com.facebook.orca (Messenger)
- com.facebook.lasso (Lasso)

### How-to
##### [REQUIRES ROOT]

1. Get root shell in your device:
```
$(comp): adb shell
$(phone): su
```

2. Pull libcoldstart.so from your desired Facebook application:
```
#(phone): cp /data/data/com.facebook.katana/lib-xzs/libcoldstart.so /sdcard/libcoldstart.so
#(phone): exit
$(phone): exit
$(comp): adb pull /sdcard/libcoldstart.so FBUnpinner/
```
3. Patch the file:
```
$ python3 patch.py
```
4. Replace libcoldstart.so in the phone with the patched version:
```
$(comp): adb push libcoldstart-patched.so /sdcard/libcoldstart.so
$(comp): adb shell
$(phone): su
#(phone): cp /sdcard/libcoldstart.so /data/data/com.facebook.katana/lib-xzs/libcoldstart.so
#(phone): chmod 777 /data/data/com.facebook.katana/lib-xzs/libcoldstart.so
```

### Want to help?
Would be cool if somebody would automate these steps, thx :)

### Reference
https://serializethoughts.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/
