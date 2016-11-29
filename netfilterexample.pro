TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue
LIBS += -L/usr/local/lib
SOURCES += main.cpp
