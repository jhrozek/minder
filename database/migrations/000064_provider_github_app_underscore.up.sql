-- Copyright 2024 Stacklok, Inc
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

BEGIN;

-- Update the definition field replacing 'github-app' with 'github_app'
-- there is a bit of trickery that Jakub pulled together from different documentation
UPDATE providers
SET definition = jsonb_set(
    -- definition - 'github-app' is the old configuration without the "github-app" key
    -- see https://www.postgresql.org/docs/current/functions-json.html section 9.46
    -- additional jsonb operators
        definition - 'github-app',
    -- this add the new key which will be named 'github_app'
        '{github_app}',
    -- this is the value of the new key which is taken from the old key
    -- see https://www.postgresql.org/docs/current/functions-json.html section 9.45
    -- json and jsonb operators
        definition -> 'github-app'
                 )
-- this is the where clause that will only update the rows that have the old key
-- and ignore the rows that have the old key
WHERE definition ? 'github-app';

COMMIT;
