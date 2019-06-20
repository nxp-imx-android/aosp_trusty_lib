/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <time.h>

/*
 * strftime ends up depending on time zone data files. Stub this function rather
 * than stubbing out data loading.
 */
size_t strftime_l(char* restrict s,
                  size_t n,
                  const char* restrict f,
                  const struct tm* restrict tm,
                  locale_t loc) {
    if (n) {
        s[0] = 0;
    }
    return 0;
}

size_t strftime(char* restrict s,
                size_t n,
                const char* restrict f,
                const struct tm* restrict tm) {
    return strftime_l(s, n, f, tm, 0);
}
