---
description: Elastic notes
---

# Elastic

Filebeat installation: https://www.elastic.co/downloads/beats/filebeat

Elastic errors: 

- https://stackoverflow.com/questions/50609417/elasticsearch-error-cluster-block-exception-forbidden-12-index-read-only-all
- https://kb.objectrocket.com/elasticsearch/how-to-fix-the-forbidden-12-read-only-api-error-in-elasticsearch-282

    PUT _cluster/settings
    {
      "transient": {
        "cluster.routing.allocation.disk.watermark.low": "10gb",
        "cluster.routing.allocation.disk.watermark.high": "5gb",
        "cluster.routing.allocation.disk.watermark.flood_stage": "2gb",
        "cluster.info.update.interval": "1m"
      }
    }

via curl:

    curl --header 'Content-Type: application/json' -XPUT http://localhost:9200/_cluster/settings -d '{
     "transient": {
       "cluster.routing.allocation.disk.watermark.low": "10gb",
       "cluster.routing.allocation.disk.watermark.high": "5gb",
       "cluster.routing.allocation.disk.watermark.flood_stage": "2gb",
       "cluster.info.update.interval": "1m"
     }
    }' 

Delete index:
    
    curl -XDELETE localhost:9200/indexName
    
Configure mapping:

    DELETE netcap-audit-records
    PUT netcap-audit-records
    PUT /netcap-audit-records/_mapping
    {
        "properties": {
        "Timestamp": {
            "type": "date"
        },
        "Version": {
            "type": "text"
        },
        "ID": {
            "type": "text"
        },
        "Protocol": {
            "type": "text"
        }
    }
    }

Create index pattern:
    
    curl -X POST "http://localhost:5601/api/saved_objects/index-pattern" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d'
     {
    "attributes": {
     "title": "netcap-ethernet*",
     "timeFieldName": "time"
     }
    }'
    
curl -X GET "${KIBANA_ENDPOINT}/api/saved_objects/_find?type=index-pattern&search_fields=title&search=netcap*" -H 'kbn-xsrf: true' --user "elastic:$ELASTIC_PASS"

curl -X DELETE "${KIBANA_ENDPOINT}/api/saved_objects/index_pattern/f245ba40-e1a9-11ea-a16f-af07127330c7" -H 'kbn-xsrf: true' --user "elastic:$ELASTIC_PASS"

Increase field limit:
    
    PUT netcap-http/_settings
    {
      "index.mapping.total_fields.limit": 10000
    }