-- Copyright 2023 Stacklok, Inc
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

-- Start to make sure the function and trigger are either both added or none
BEGIN;

CREATE OR REPLACE FUNCTION update_profile_status() RETURNS TRIGGER AS $$
DECLARE
    v_status eval_status_types;
    v_profile_id UUID;
    row rule_details_eval%ROWTYPE;
BEGIN
    -- Fetch the profile_id for the current rule_eval_id
    SELECT profile_id INTO v_profile_id
    FROM rule_evaluations
    WHERE id = NEW.rule_eval_id;

    RAISE LOG 'New Rule Evaluation ID: % status %', NEW.rule_eval_id, NEW.status;
    RAISE LOG 'old Rule Evaluation ID: % status %', OLD.rule_eval_id, OLD.status;

    FOR row IN SELECT * FROM rule_details_eval rde INNER JOIN rule_evaluations res ON res.id = rde.rule_eval_id WHERE res.profile_id = v_profile_id LOOP
            RAISE LOG 'Profile ID: % Row: %', v_profile_id, row;
    END LOOP;

    SELECT CASE
               WHEN EXISTS (
                   SELECT 1 FROM rule_details_eval rde
                                     INNER JOIN rule_evaluations res ON res.id = rde.rule_eval_id
                   WHERE res.profile_id = profile_id AND status = 'error'
               ) THEN 'error'
               WHEN EXISTS (
                   SELECT 1 FROM rule_details_eval rde
                                     INNER JOIN rule_evaluations res ON res.id = rde.rule_eval_id
                   WHERE res.profile_id = profile_id AND status = 'failure'
               ) THEN 'failure'
               WHEN NOT EXISTS (
                   SELECT 1 FROM rule_details_eval rde
                                     INNER JOIN rule_evaluations res ON res.id = rde.rule_eval_id
                   WHERE res.profile_id = profile_id
               ) THEN 'pending'
               WHEN NOT EXISTS (
                   SELECT 1 FROM rule_details_eval rde
                                     INNER JOIN rule_evaluations res ON res.id = rde.rule_eval_id
                   WHERE res.profile_id = profile_id AND status != 'skipped'
               ) THEN 'skipped'
               WHEN NOT EXISTS (
                   SELECT 1 FROM rule_details_eval rde
                                     INNER JOIN rule_evaluations res ON res.id = rde.rule_eval_id
                   WHERE res.profile_id = profile_id AND status NOT IN ('success', 'skipped')
               ) THEN 'success'
               ELSE (
                   'error' -- This should never happen, if yes, make it visible
                   )
               END INTO v_status;

    UPDATE profile_status SET profile_status = v_status, last_updated = NOW()
    WHERE res.profile_id = profile_id;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- transaction commit
COMMIT;
