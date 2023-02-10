set input=%1%
@echo off
mkdir release32
clang++ --target=i686-pc-windows-msvc -c Global.cpp -o ./release32/Global.o
clang++ --target=i686-pc-windows-msvc -c BeaconBof.cpp -o ./release32/BeaconBof.o
clang++ --target=i686-pc-windows-msvc -c BeaconFileManage.cpp -o ./release32/BeaconFileManage.o
clang++ --target=i686-pc-windows-msvc -c BeaconInject.cpp -o ./release32/BeaconInject.o
clang++ --target=i686-pc-windows-msvc -c BeaconJob.cpp -o ./release32/BeaconJob.o
clang++ --target=i686-pc-windows-msvc -c BeaconLateralMovement.cpp -o ./release32/BeaconLateralMovement.o
clang++ --target=i686-pc-windows-msvc -c Beaconrportfwd.cpp -o ./release32/Beaconrportfwd.o
clang++ --target=i686-pc-windows-msvc -c BeaconSleep.cpp -o ./release32/BeaconSleep.o
clang++ --target=i686-pc-windows-msvc -c BeaconTask.cpp -o ./release32/BeaconTask.o
clang++ --target=i686-pc-windows-msvc -c BeaconX64.cpp -o ./release32/BeaconX64.o
clang++ --target=i686-pc-windows-msvc -c ChildBeacon.cpp -o ./release32/ChildBeacon.o
clang++ --target=i686-pc-windows-msvc -c comm.cpp -o ./release32/comm.o
clang++ --target=i686-pc-windows-msvc -c common.cpp -o ./release32/common.o
clang++ --target=i686-pc-windows-msvc -c encrypt_decrypt.cpp -o ./release32/encrypt_decrypt.o
clang++ --target=i686-pc-windows-msvc -c rotation.cpp -o ./release32/rotation.o
clang++ --target=i686-pc-windows-msvc -c Utils.cpp -o ./release32/Utils.o
echo "success" > %input%
exit