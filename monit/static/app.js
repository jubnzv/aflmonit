function formatDate(unixtime) {
  var newDate = new Date();
  newDate.setTime(unixtime * 1000);
  return newDate.toUTCString();
}

var app = new Vue({
  el: "#app",
  data: {
    fuzzer_stats: {},
    crashes: [],
    hangs: [],
    timer: null,
  },
  mounted: function () {
    this.receiveAll();
    this.timer = setInterval(() => {
      this.receiveAll();
    }, 5000);
  },
  methods: {
    receiveAll: function () {
      this.receiveStats();
      this.receiveCrashes();
      this.receiveHangs();
    },
    receiveStats: function () {
      axios
        .post("/api/v1/fuzzer_stats", { source: this.fuzzer_stats })
        .then((response) => {
          this.fuzzer_stats = response.data;
          if (this.fuzzer_stats.start_time !== "undefined") {
            this.fuzzer_stats.start_time = formatDate(
              this.fuzzer_stats.start_time
            );
          }
          if (this.fuzzer_stats.last_update !== "undefined") {
            this.fuzzer_stats.last_update = formatDate(
              this.fuzzer_stats.last_update
            );
          }
        });
    },
    receiveCrashes: function () {
      axios
        .post("/api/v1/crashes", { source: this.crashes })
        .then((response) => {
          this.crashes = response.data;
        });
    },
    receiveHangs: function () {
      axios.post("/api/v1/hangs", { source: this.hangs }).then((response) => {
        this.hangs = response.data;
      });
    },
  },
  delimiters: ["[[", "]]"],
});
