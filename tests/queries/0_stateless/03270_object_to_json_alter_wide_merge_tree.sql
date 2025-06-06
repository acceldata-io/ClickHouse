-- Tags: long, no-object-storage
-- - no-object-storage: too slow

set allow_experimental_object_type = 1;
SET enable_json_type = 1;
set max_block_size = 100;
set max_insert_block_size = 100;
set min_insert_block_size_rows = 100;
set output_format_json_quote_64bit_integers = 0;
set max_execution_time = 300;

drop table if exists test;

create table test (json Object('json')) engine=MergeTree order by tuple() settings min_rows_for_wide_part=1, min_bytes_for_wide_part=1;
insert into test select toJSONString(map('a' || number % 100, number)) from numbers(1000);
alter table test modify column json JSON();
select distinctJSONPathsAndTypes(json) from test;
select distinct json.a0 from test order by json.a0.:Int64;
select distinct json.a99 from test order by json.a99.:Int64;
drop table test;

create table test (json Object('json')) engine=MergeTree order by tuple() settings min_rows_for_wide_part=1, min_bytes_for_wide_part=1;
insert into test select toJSONString(map('a' || number % 100, number)) from numbers(1000);
alter table test modify column json JSON(max_dynamic_paths=10);
select distinctJSONPathsAndTypes(json) from test;
select distinct json.a0 from test order by json.a0.:Int64;
select distinct json.a99 from test order by json.a99.:Int64;
drop table test;
