(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        // AMD. Register as an anonymous module.
        define(['exports', 'echarts'], factory);
    } else if (typeof exports === 'object' && typeof exports.nodeName !== 'string') {
        // CommonJS
        factory(exports, require('echarts'));
    } else {
        // Browser globals
        factory({}, root.echarts);
    }
}(this, function (exports, echarts) {
    var log = function (msg) {
        if (typeof console !== 'undefined') {
            console && console.error && console.error(msg);
        }
    };
    if (!echarts) {
        log('ECharts is not Loaded');
        return;
    }
    echarts.registerTheme('westeros', {
        "color": [
            "#3b82f6",
            "#8b5cf6",
            "#38bdf8",
            "#a78bfa",
            "#34d399",
            "#fbbf24"
        ],
        "backgroundColor": "#050508",
        "textStyle": {
            "color": "#f4f7fb"
        },
        "title": {
            "textStyle": {
                "color": "#60a5fa"
            },
            "subtextStyle": {
                "color": "#a78bfa"
            }
        },
        "line": {
            "itemStyle": {
                "borderWidth": "2"
            },
            "lineStyle": {
                "width": "2"
            },
            "symbolSize": "6",
            "symbol": "circle",
            "smooth": true
        },
        "radar": {
            "itemStyle": {
                "borderWidth": "2"
            },
            "lineStyle": {
                "width": "2"
            },
            "symbolSize": "6",
            "symbol": "circle",
            "smooth": true
        },
        "bar": {
            "itemStyle": {
                "barBorderWidth": 0,
                "barBorderColor": "#ccc"
            }
        },
        "pie": {
            "itemStyle": {
                "borderWidth": 0,
                "borderColor": "#ccc"
            }
        },
        "scatter": {
            "itemStyle": {
                "borderWidth": 0,
                "borderColor": "#ccc"
            }
        },
        "boxplot": {
            "itemStyle": {
                "borderWidth": 0,
                "borderColor": "#ccc"
            }
        },
        "parallel": {
            "itemStyle": {
                "borderWidth": 0,
                "borderColor": "#ccc"
            }
        },
        "sankey": {
            "itemStyle": {
                "borderWidth": 1,
                "borderColor": "#24283a"
            },
            "lineStyle": {
                "color": "gradient",
                "opacity": 0.38
            }
        },
        "treemap": {
            "itemStyle": {
                "borderWidth": 2,
                "borderColor": "#050508",
                "gapWidth": 2
            }
        },
        "sunburst": {
            "itemStyle": {
                "borderWidth": 2,
                "borderColor": "#050508"
            }
        },
        "funnel": {
            "itemStyle": {
                "borderWidth": 0,
                "borderColor": "#ccc"
            }
        },
        "gauge": {
            "itemStyle": {
                "borderWidth": 0,
                "borderColor": "#ccc"
            }
        },
        "candlestick": {
            "itemStyle": {
                "color": "#8b5cf6",
                "color0": "transparent",
                "borderColor": "#a78bfa",
                "borderColor0": "#38bdf8",
                "borderWidth": "2"
            }
        },
        "graph": {
            "itemStyle": {
                "borderWidth": 2,
                "borderColor": "#38bdf8"
            },
            "lineStyle": {
                "width": 1,
                "color": "#596177",
                "opacity": 0.72
            },
            "symbolSize": "6",
            "symbol": "circle",
            "smooth": true,
            "color": [
                "#3b82f6",
                "#8b5cf6",
                "#38bdf8",
                "#a78bfa",
                "#34d399",
                "#fbbf24"
            ],
            "label": {
                "color": "#eeeeee"
            }
        },
        "map": {
            "itemStyle": {
                "normal": {
                    "areaColor": "#151827",
                    "borderColor": "#3b82f6",
                    "borderWidth": 0.5
                },
                "emphasis": {
                    "areaColor": "#263d70",
                    "borderColor": "#60a5fa",
                    "borderWidth": 1
                }
            },
            "label": {
                "normal": {
                    "textStyle": {
                        "color": "#f4f7fb"
                    }
                },
                "emphasis": {
                    "textStyle": {
                        "color": "#ffffff"
                    }
                }
            }
        },
        "geo": {
            "itemStyle": {
                "normal": {
                    "areaColor": "#151827",
                    "borderColor": "#3b82f6",
                    "borderWidth": 0.5
                },
                "emphasis": {
                    "areaColor": "#263d70",
                    "borderColor": "#60a5fa",
                    "borderWidth": 1
                }
            },
            "label": {
                "normal": {
                    "textStyle": {
                        "color": "#f4f7fb"
                    }
                },
                "emphasis": {
                    "textStyle": {
                        "color": "#ffffff"
                    }
                }
            }
        },
        "categoryAxis": {
            "axisLine": {
                "show": true,
                "lineStyle": {
                    "color": "#596177"
                }
            },
            "axisTick": {
                "show": false,
                "lineStyle": {
                    "color": "#333"
                }
            },
            "axisLabel": {
                "show": true,
                "textStyle": {
                    "color": "#9199ad"
                }
            },
            "splitLine": {
                "show": true,
                "lineStyle": {
                    "color": [
                        "#24283a"
                    ]
                }
            },
            "splitArea": {
                "show": false,
                "areaStyle": {
                    "color": [
                        "rgba(250,250,250,0.05)",
                        "rgba(200,200,200,0.02)"
                    ]
                }
            }
        },
        "valueAxis": {
            "axisLine": {
                "show": true,
                "lineStyle": {
                    "color": "#596177"
                }
            },
            "axisTick": {
                "show": false,
                "lineStyle": {
                    "color": "#333"
                }
            },
            "axisLabel": {
                "show": true,
                "textStyle": {
                    "color": "#9199ad"
                }
            },
            "splitLine": {
                "show": true,
                "lineStyle": {
                    "color": [
                        "#24283a"
                    ]
                }
            },
            "splitArea": {
                "show": false,
                "areaStyle": {
                    "color": [
                        "rgba(250,250,250,0.05)",
                        "rgba(200,200,200,0.02)"
                    ]
                }
            }
        },
        "logAxis": {
            "axisLine": {
                "show": true,
                "lineStyle": {
                    "color": "#596177"
                }
            },
            "axisTick": {
                "show": false,
                "lineStyle": {
                    "color": "#333"
                }
            },
            "axisLabel": {
                "show": true,
                "textStyle": {
                    "color": "#9199ad"
                }
            },
            "splitLine": {
                "show": true,
                "lineStyle": {
                    "color": [
                        "#24283a"
                    ]
                }
            },
            "splitArea": {
                "show": false,
                "areaStyle": {
                    "color": [
                        "rgba(250,250,250,0.05)",
                        "rgba(200,200,200,0.02)"
                    ]
                }
            }
        },
        "timeAxis": {
            "axisLine": {
                "show": true,
                "lineStyle": {
                    "color": "#596177"
                }
            },
            "axisTick": {
                "show": false,
                "lineStyle": {
                    "color": "#333"
                }
            },
            "axisLabel": {
                "show": true,
                "textStyle": {
                    "color": "#9199ad"
                }
            },
            "splitLine": {
                "show": true,
                "lineStyle": {
                    "color": [
                        "#24283a"
                    ]
                }
            },
            "splitArea": {
                "show": false,
                "areaStyle": {
                    "color": [
                        "rgba(250,250,250,0.05)",
                        "rgba(200,200,200,0.02)"
                    ]
                }
            }
        },
        "toolbox": {
            "iconStyle": {
                "normal": {
                    "borderColor": "#9199ad"
                },
                "emphasis": {
                    "borderColor": "#60a5fa"
                }
            }
        },
        "legend": {
            "textStyle": {
                "color": "#9199ad"
            }
        },
        "tooltip": {
            "axisPointer": {
                "lineStyle": {
                    "color": "#596177",
                    "width": 1
                },
                "crossStyle": {
                    "color": "#596177",
                    "width": 1
                }
            }
        },
        "timeline": {
            "lineStyle": {
                "color": "#3b82f6",
                "width": 1
            },
            "itemStyle": {
                "normal": {
                    "color": "#3b82f6",
                    "borderWidth": 1
                },
                "emphasis": {
                    "color": "#8b5cf6"
                }
            },
            "controlStyle": {
                "normal": {
                    "color": "#3b82f6",
                    "borderColor": "#3b82f6",
                    "borderWidth": 0.5
                },
                "emphasis": {
                    "color": "#8b5cf6",
                    "borderColor": "#8b5cf6",
                    "borderWidth": 0.5
                }
            },
            "checkpointStyle": {
                "color": "#8b5cf6",
                "borderColor": "#a78bfa"
            },
            "label": {
                "normal": {
                    "textStyle": {
                        "color": "#9199ad"
                    }
                },
                "emphasis": {
                    "textStyle": {
                        "color": "#f4f7fb"
                    }
                }
            }
        },
        "visualMap": {
            "color": [
                "#8b5cf6",
                "#3b82f6",
                "#38bdf8"
            ]
        },
        "dataZoom": {
            "backgroundColor": "rgba(0,0,0,0)",
            "dataBackgroundColor": "rgba(255,255,255,0.3)",
            "fillerColor": "rgba(167,183,204,0.4)",
            "handleColor": "#a7b7cc",
            "handleSize": "100%",
            "textStyle": {
                "color": "#9199ad"
            }
        },
        "markPoint": {
            "label": {
                "color": "#eeeeee"
            },
            "emphasis": {
                "label": {
                    "color": "#eeeeee"
                }
            }
        }
    });
}));
