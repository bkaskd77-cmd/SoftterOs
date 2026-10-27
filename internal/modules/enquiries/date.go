package enquiries

import "time"

const travelDateLayout = "2006-01-02"

func parseTravelDate(value string) (time.Time, bool) {
	if len(value) != len(travelDateLayout) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(travelDateLayout, value)
	if err != nil || parsed.Year() < 1 || parsed.Format(travelDateLayout) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func validTravelDates(startValue, endValue string) bool {
	if startValue == "" && endValue == "" {
		return true
	}
	start, startOK := parseTravelDate(startValue)
	end, endOK := parseTravelDate(endValue)
	return startOK && endOK && !end.Before(start)
}
