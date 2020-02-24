/*
 * Copyright 2020 Sergio Rando <segio.rando@yahoo.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"use strict";

import { Example as ModuleExample } from "./modules/module.js"
import { Example as ExternalExample } from "./../../../src/external/example.js"
import { Example as Example } from "./../js-example/modules/module.js"

platform.console.log('js-template/test', ModuleExample);
platform.console.log('js-template/test', ExternalExample);
platform.console.log('js-template/test', Example);
