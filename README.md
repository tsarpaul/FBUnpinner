# FBUnpinner
## Works for Instagram & Facebook

SUPPORTS:<br> 
**TLS1.3 & TLS1.2** for x86/ARM32/ARM64<br>
Instagram x86 currently does not work, feel free to open a pull request :)
<hr/>

A script to automate removing certificate pinning defense from Facebook applications.

TESTED FOR THE FOLLOWING APPS:
- com.facebook.katana (Facebook for Android)
- com.facebook.orca (Messenger)
- com.facebook.lasso (Lasso)
- com.instagram.android (Instagram for Android)

### How-to
##### [REQUIRES ROOT]

* <b>Note: for Instagram replace lib-xzs/libcoldstart.so with lib-zstd/libliger.so</b>

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
OR:
```
$ python3 patch.py libliger.so libliger-patched.so
```


5. Replace libcoldstart.so in the phone with the patched version:
```
$(comp): adb push libcoldstart-patched.so /sdcard/libcoldstart.so
$(comp): adb shell
$(phone): su
#(phone): cp /sdcard/libcoldstart.so /data/data/com.facebook.katana/lib-xzs/libcoldstart.so
#(phone): chmod 777 /data/data/com.facebook.katana/lib-xzs/libcoldstart.so
```
6. (Optional) Setting up Burp to work with TLS 1.3 ("no cipher suites in common")
```
<path_to_jdk>/jdk-11.0.2.jdk/Contents/Home/bin/java -jar burpsuite_community.jar
```

### TODO
A script to just patch an APK

### Tested Emulators
Android Studio:
  Nexus_6_API_24 - Google APIs Intel Atom (x86)


Genymotion:
  Google Nexus 5X API 26 (x86)

### Reference
https://serializethoughts.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/ <br/>
https://plainsec.org/how-to-bypass-instagram-ssl-pinning-on-android-v78/
