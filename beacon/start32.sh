mkdir release32
x86_64-w64-mingw32-g++ -c Global.cpp -o ./release32/Global.o
x86_64-w64-mingw32-g++ -c BeaconBof.cpp -o ./release32/BeaconBof.o
x86_64-w64-mingw32-g++ -c BeaconFileManage.cpp -o ./release32/BeaconFileManage.o
x86_64-w64-mingw32-g++ -c BeaconInject.cpp -o ./release32/BeaconInject.o
x86_64-w64-mingw32-g++ -c BeaconJob.cpp -o ./release32/BeaconJob.o
x86_64-w64-mingw32-g++ -c BeaconLateralMovement.cpp -o ./release32/BeaconLateralMovement.o
x86_64-w64-mingw32-g++ -c Beaconrportfwd.cpp -o ./release32/Beaconrportfwd.o
x86_64-w64-mingw32-g++ -c BeaconSleep.cpp -o ./release32/BeaconSleep.o
x86_64-w64-mingw32-g++ -c BeaconTask.cpp -o ./release32/BeaconTask.o
x86_64-w64-mingw32-g++ -c BeaconX64.cpp -o ./release32/BeaconX64.o
x86_64-w64-mingw32-g++ -c ChildBeacon.cpp -o ./release32/ChildBeacon.o
x86_64-w64-mingw32-g++ -c comm.cpp -o ./release32/comm.o
x86_64-w64-mingw32-g++ -c common.cpp -o ./release32/common.o
x86_64-w64-mingw32-g++ -c encrypt_decrypt.cpp -o ./release32/encrypt_decrypt.o
x86_64-w64-mingw32-g++ -c rotation.cpp -o ./release32/rotation.o
x86_64-w64-mingw32-g++ -c Utils.cpp -o ./release32/Utils.o
x86_64-w64-mingw32-g++ -c c2profile.cpp -o ./release32/c2profile.o
x86_64-w64-mingw32-g++ -L ./ beaconMain.cpp ./release32/c2profile.o ./release32/Utils.o ./release32/rotation.o ./release32/Global.o ./release32/encrypt_decrypt.o ./release32/common.o ./release32/comm.o ./release32/ChildBeacon.o ./release32/BeaconX64.o ./release32/BeaconTask.o ./release32/BeaconSleep.o ./release32/Beaconrportfwd.o ./release32/BeaconLateralMovement.o ./release32/BeaconJob.o ./release32/BeaconInject.o ./release32/BeaconFileManage.o ./release32/BeaconBof.o -o ./release32/beacon.exe
echo "success" > ../tt