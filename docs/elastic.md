---
description: Elastic notes
---

# setup

## permissions for mounted directories

- dirs must be owned by uid 1000:1000
- kibana.yml and elasticsearch ymal must have chmod 644

## reset test license: remove data dir

  rm -r /mnt/storage/elasticsearch

## TLS required when using basic license

  serverconfig » [1/1] executing shell
  [root@host elasticsearch]# curl -X POST "localhost:9200/_license/start_trial?acknowledge=true&pretty"
  {
  "acknowledged" : true,
  "trial_was_started" : true,
  "type" : "trial"
  }
  [root@host elasticsearch]# elasticsearch-setup-passwords interactive

> if using a reverse proxy like traefik: use the same username and password as basic auth 

## Find objects API

> todo: automate index and mapping and index pattern reset

https://www.elastic.co/guide/en/kibana/current/saved-objects-api-find.html

# Metricbeat

    metricbeat modules enable golang system
    metricbeat setup -e

See:

- https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-installation-configuration.html
- https://www.elastic.co/guide/en/beats/metricbeat/current/configuration-metricbeat.html
- https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-system.html

Example: run net capture with metrics flag to expose metrics during operation (both prometheus and expvar)
    
   net capture -iface=XXXX -metrics=localhost:6060

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

Increase field limit for selected audit records:
    
    PUT netcap-http/_settings
    {
      "index.mapping.total_fields.limit": 10000
    }
 
TCP anomalies query:
   
    {
      "description": "TCP Anomalies",
      "source": {
        "index": "netcap-tcp*"
      },
      "dest": {
        "index": "netcap-outliers-tcp"
      },
      "analyzed_fields": {
        "includes": [
                    "SrcPort",	
                    "DstPort",
                    "SYN",
                    "ACK",
                    "RST",
                    "FIN",
                    "PayloadSize"]
      },
      "analysis": {
        "outlier_detection": {}
      },
      "model_memory_limit": "5000mb"
    }

TCP Flag anomalies:
    
    {
      "description": "TCP Anomalies",
      "source": {
        "index": "netcap-tcp*"
      },
      "dest": {
        "index": "netcap-outliers-tcp"
      },
      "analyzed_fields": {
        "includes": [
                    "SYN",
                    "ACK",
                    "RST",
                    "FIN"]
      },
      "analysis": {
        "outlier_detection": {}
      },
      "model_memory_limit": "5000mb"
    }

Configure indices:
    
    /root/net capture -elastic-user elastic -elastic-pass "$ELASTIC_PASS" -kibana "https://dreadl0ck.net:5443" -gen-elastic-indices
    
Manually increase limit for selected audit record field count:

    PUT netcap-v2-http/_settings
    {
      "index.mapping.total_fields.limit": 10000000
    }
    
> HTTP audit records usually have a high number of fields because parameter and header names are stored as a unique fields.

Ingest data from PCAP directory:
    
    rm -rf snort.log.142* && rm -f screenlog.0
    screen -L time ./analyze.sh FIRST-2015_Hands-on_Network_Forensics_PCAP

Increase Java heap size:
    
    # micro /etc/elasticsearch/jvm.options.d/elastic.options

add limits:

    -Xms12g
    -Xmx12g

restart elastic:

    # chown elasticsearch /etc/elasticsearch/jvm.options.d/elastic.options
    # systemctl restart elasticsearch.service
    
search screenlog for unique errors:
    
    grep "Error:" screenlog.0 | cut -d "]" -f 2 | sort | uniq