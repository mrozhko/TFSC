#include "time_report.h"
#include "../utils/time_util.h"
#include "../utils/MagicSingleton.h"
#include "../include/logging.h"
#include <iostream>

TimeReport::TimeReport() : title_("Elapsed time:"), start_(0), end_(0)
{
    Init();
}

TimeReport::TimeReport(const string& title) : title_(title), start_(0), end_(0)
{
    Init();
}

TimeReport::~TimeReport()
{
    // End();
    // Report();
}

void TimeReport::Init()
{
    start_ = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
}

void TimeReport::End()
{
    end_ = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
}

void TimeReport::Report()
{
    Report(title_);
}

void TimeReport::Report(const string& title)
{
    End();
    int64_t usedTime = end_ - start_;
    double dUsendTime = ((double)usedTime) / 1000000.0;

    std::cout << title << " " << dUsendTime << " second" << std::endl;
}
