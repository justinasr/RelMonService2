<?php
if (!isset($_SERVER["PATH_INFO"])) {
?>
  <!doctype html>
  <html lang="en">
    <head>
      <!-- Required meta tags -->
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <link rel="icon" href="favicon.png">
      <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:100,300,400,500,700,900">

      <!-- Bootstrap CSS -->
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
      <link rel="stylesheet" type="text/css" href="style.css">
      <script  src="https://code.jquery.com/jquery-3.4.1.min.js" integrity="sha256-CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=" crossorigin="anonymous"></script>
      <script>
        function deleteRelmon(filename, niceName){
          if (confirm("Are you sure you want to delete " + niceName + "?")) {
            $.post("delete.php", { "name": filename },function(data, status) {
              alert("Status: " + status);
              location.reload();
            });
          }
        }
      </script>
      <title>RelMon Reports</title>
    </head>
    <body>
      <header class="v-sheet v-sheet--tile theme--light v-toolbar v-app-bar v-app-bar--fixed elevation-3" data-booted="true" style="height: 64px; margin-top: 0px; transform: translateY(0px); left: 0px; right: 0px; position: fixed; z-index: 999;">
        <div class="v-toolbar__content" style="height: 64px;">
          <a href="/relmon/" style="text-decoration: none; color: rgba(0, 0, 0, 0.87);">
            <div class="headline">
              <span>RelMon</span><span class="font-weight-light">Reports</span>
            </div>
          </a>
        </div>
      </header>
      <div class="container" style="padding: 76px 12px 12px 12px;">
        <div class="row card elevation-3">
          <div class="card-body" style="padding-bottom: 8px;">
            <ul>
              <li><a target='_blank' href="https://cmsweb.cern.ch/dqm/online">Link to the Online DQM GUI</a></li>
              <li><a target='_blank' href="https://cmsweb.cern.ch/dqm/offline">Link to the Offline DQM GUI</a></li>
              <li><a target='_blank' href="https://cmsweb.cern.ch/dqm/relval">Link to the RelVal DQM GUI</a></li>
              <li><a target='_blank' href="https://cmsweb.cern.ch/dqm/relval/data/browse/ROOT/RelValData/">Link to the Data RelVal files</a></li>
              <li><a target='_blank' href="https://cmsweb.cern.ch/dqm/relval/data/browse/ROOT/RelVal/">Link to the MC RelVal files</a></li>
            </ul>

            <div class="row">
              <div class="col-sm-12 col-md-3" style="margin: 0; padding: 0;">
              </div>
              <div class="col-sm-12 col-md-6" style="margin: 0; padding: 0;">
                <form >
                  <div style="display: flex; border-radius: 4px; margin: 4px;" class="elevation-3">
                    <div style="border: 0.5px solid rgba(0, 0, 0, 0.42); flex-grow: 1; border-radius: 4px 0px 0px 4px;">
                      <input type="text" name="q" id="q" style="width: 100%; height: 100%; padding: 0 0 0 8px; background-color: transparent; border: none; color: rgba(0, 0, 0, 0.67);" placeholder="RelMon name or ID"/>
                    </div>
                    <button type="submit" class="vuetify-button" style="border-radius: 0 4px 4px 0">Search</button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>

  <?php
        $relmons = glob('./*.sqlite');
        if (isset($_GET["q"])) {
            $q = $_GET["q"];
            $regexQuery = str_replace("*", ".*", "/*" . $q . "*/i");
            $relmons = array_filter($relmons, function($k) use ($regexQuery) {
              return preg_match($regexQuery, $k);
            });
        } else {
            $relmons = array_filter($relmons, function ($name) {return strpos($name, "RELMON_TEST") === false;});
        }
        usort($relmons, function($a, $b) { return filemtime($a) < filemtime($b); });
        $totalRelmons = count($relmons);
        $page = 0;
        $pageSize = 10;
        if (isset($_GET["page"])) {
            $page = $_GET["page"];
        }
        $relmons = array_slice($relmons, $page * $pageSize, $pageSize);

        foreach($relmons as $relmon) {
  ?>
          <div class="row card mt-2 elevation-3">
            <div class="card-body">
              <div class="row">
                <div class="col-sm-12 col-md-8">
  <?php
                  $stat = stat($relmon);
                  $lastModified = date("Y-m-d H:i", $stat['mtime']);
                  $size = round($stat['size'] / (1024.0 * 1024.0), 2);
                  $relmonName = str_replace("./", "", $relmon);
                  $relmonName = str_replace(".sqlite", "", $relmonName);
                  $explodedRelmonName = explode("___", $relmonName);
                  array_shift($explodedRelmonName);
                  $niceRelmonName = join("___", $explodedRelmonName);
                  print("<a href=\"?q=$niceRelmonName\" class=\"bigger-text\" id=\"$niceRelmonName\">$niceRelmonName</a><br>");
                  print("<span class=\"font-weight-light\">Created:</span> $lastModified</span><br>");
                  print("<span class=\"font-weight-light\">Size:</span> $size MB");
  ?>
                </div>
                <div class="col-sm-12 col-md-4">
                  <span class="bigger-text font-weight-light">Subcategories:</span>
                  <ul>
  <?php
                    try {
                      $handle = new SQLite3($relmon);
                      $tablesquery = $handle->query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;");
                      while ($table = $tablesquery->fetchArray(SQLITE3_ASSOC)) {
                        $category = $table['name'];
                        print("<li><a href=\"$relmonName/$category/RelMonSummary.html\">$category</a></li>");
                      }
                      $handle->close();
                    } catch (Exception $e) {
                      print("<li><i>Error getting subcategories. Error:" + $e->getMessage());
                    }
  ?>
                  </ul>
                </div>
              </div>
            </div>
          </div>
  <?php
        }
        if ($totalRelmons > $pageSize) {
          $actionString = "?";
          if ($q) {
            $actionString = $actionString . "q=" . $q . "&";
          }
          $actionString = $actionString . "page=";
  ?>
          <div class="row card mt-2 elevation-3">
            <div class="card-body">
              <div class="row" style="height: 28px;">
                <div class="col-sm-4">
  <?php
                  if ($page > 0) {
                    print('<a href="' . $actionString . ($page - 1) . '" style="float: left"><div class="vuetify-button elevation-3" style="border-radius: 4px; line-height: 28px;">Previous Page</div></a>');
                  }
  ?>
                </div>
                <div class="col-sm-4" style="text-align: center;">
                  <span class="font-weight-light">Pages:</span>
  <?php
                  $totalPages = max(1, ceil($totalRelmons / max(1, $pageSize)));
                  for ($i = 0; $i < $totalPages; $i++) {
                    if ($i == $page) {
                      print('<b>' . $i . '</b> ');
                    } else {
                      print('<a href="' . $actionString . $i .'">' . $i .'</a> ');
                    }
                  }
  ?>
                </div>
                <div class="col-sm-4">
  <?php
                  if (($page + 1) * $pageSize < $totalRelmons) {
                    print('<a href="' . $actionString . ($page + 1) . '" style="float: right"><div class="vuetify-button elevation-3" style="border-radius: 4px; line-height: 28px;">Next Page</div></a>');
                  }
  ?>
                </div>
              </div>
            </div>
          </div>
  <?php
        }
  ?>
      </div>
    </body>
  </html>
<?php
} else {
  header("Content-Encoding: gzip");
  header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T', time() + (5))); # 5 seconds
  header('Cache-Control: no-store, no-cache, must-revalidate');
  header('Cache-Control: post-check=0, pre-check=0', FALSE);
  header('Pragma: no-cache');
  header('PATH: ' .$_SERVER["PATH_INFO"]);
  $pathArray = explode("/", $_SERVER["PATH_INFO"]);
  $relmon = $pathArray[1];
  $category = $pathArray[2];
  $fileName = str_replace("/$relmon/", "", $_SERVER["PATH_INFO"]);
  $dbFileName = "$relmon.sqlite";
  if (!file_exists($dbFileName)) {
    echo "";
  } else {
    $handle = new SQLite3($dbFileName);
    $queryString = "SELECT htmlgz FROM $category WHERE path='$fileName';";
    $result = $handle->querySingle($queryString);
    $handle->close();
    echo $result;
  }
}
?>
