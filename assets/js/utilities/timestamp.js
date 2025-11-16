(function() {
  'use strict';
  
  const tsUnixSeconds = document.getElementById('ts-unix-seconds');
  const tsUnixMilliseconds = document.getElementById('ts-unix-milliseconds');
  const tsUnixNanoseconds = document.getElementById('ts-unix-nanoseconds');
  const tsWindows = document.getElementById('ts-windows');
  const tsIso8601 = document.getElementById('ts-iso8601');
  
  if (!tsUnixSeconds) return;
  
  let updating = false;

  function updateTimestamp(editedField) {
    if (updating) return;
    updating = true;
    
    try {
      let date = null;
      
      if (editedField === 'unix-seconds') {
        const val = tsUnixSeconds.value.trim();
        if (val) date = new Date(parseInt(val) * 1000);
      } else if (editedField === 'unix-milliseconds') {
        const val = tsUnixMilliseconds.value.trim();
        if (val) date = new Date(parseInt(val));
      } else if (editedField === 'unix-nanoseconds') {
        const val = tsUnixNanoseconds.value.trim();
        if (val) date = new Date(parseInt(val) / 1000000);
      } else if (editedField === 'windows') {
        const val = tsWindows.value.trim();
        if (val) {
          const fileTime = BigInt(val);
          const unixTime = Number(fileTime / 10000000n) - 11644473600;
          date = new Date(unixTime * 1000);
        }
      } else if (editedField === 'iso8601') {
        const val = tsIso8601.value.trim();
        if (val) date = new Date(val);
      }
      
      if (!date || isNaN(date.getTime())) {
        if (editedField !== 'unix-seconds' && tsUnixSeconds) tsUnixSeconds.value = '';
        if (editedField !== 'unix-milliseconds' && tsUnixMilliseconds) tsUnixMilliseconds.value = '';
        if (editedField !== 'unix-nanoseconds' && tsUnixNanoseconds) tsUnixNanoseconds.value = '';
        if (editedField !== 'windows' && tsWindows) tsWindows.value = '';
        if (editedField !== 'iso8601' && tsIso8601) tsIso8601.value = '';
        updating = false;
        return;
      }
      
      if (editedField !== 'unix-seconds' && tsUnixSeconds) {
        tsUnixSeconds.value = Math.floor(date.getTime() / 1000).toString();
      }
      if (editedField !== 'unix-milliseconds' && tsUnixMilliseconds) {
        tsUnixMilliseconds.value = date.getTime().toString();
      }
      if (editedField !== 'unix-nanoseconds' && tsUnixNanoseconds) {
        tsUnixNanoseconds.value = (date.getTime() * 1000000).toString();
      }
      if (editedField !== 'windows' && tsWindows) {
        const unixTime = Math.floor(date.getTime() / 1000);
        const fileTime = BigInt(unixTime + 11644473600) * 10000000n;
        tsWindows.value = fileTime.toString();
      }
      if (editedField !== 'iso8601' && tsIso8601) {
        tsIso8601.value = date.toISOString();
      }
    } catch (e) {
      // Error
    }
    
    updating = false;
  }

  tsUnixSeconds.addEventListener('input', () => updateTimestamp('unix-seconds'));
  if (tsUnixMilliseconds) tsUnixMilliseconds.addEventListener('input', () => updateTimestamp('unix-milliseconds'));
  if (tsUnixNanoseconds) tsUnixNanoseconds.addEventListener('input', () => updateTimestamp('unix-nanoseconds'));
  if (tsWindows) tsWindows.addEventListener('input', () => updateTimestamp('windows'));
  if (tsIso8601) tsIso8601.addEventListener('input', () => updateTimestamp('iso8601'));
})();
