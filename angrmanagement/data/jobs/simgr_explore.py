import logging

from PySide2.QtWidgets import QMessageBox

from .job import Job
from ...logic import GlobalInfo
from ...logic.threads import gui_thread_schedule


_l = logging.getLogger(name=__name__)


class SimgrExploreJob(Job):

    def __init__(self, simgr, find=None, avoid=None, pre_step_callback=None, post_step_callback=None,
                 until_callback=None, callback=None):
        super(SimgrExploreJob, self).__init__('Simulation manager exploring')
        self._simgr = simgr
        self._find = find
        self._avoid = avoid
        self._callback = callback
        self._post_step_callback = post_step_callback
        self._pre_step_callback = pre_step_callback
        self._until_callback = until_callback
        self._interrupted = False
        self._step_progress = 0
        self._number_states_to_step = 0

    def __repr__(self):
        return "Exploring %r" % self._simgr

    def run(self, inst):
        """Run the job. Runs in the worker thread."""

        def until_callback(*args, **kwargs):
            return self._until_callback(*args, **kwargs) or self._interrupted

        self._simgr.explore(find=self._find, avoid=self._avoid, pre_func=self.pre_step_callback,
                            step_func=self._post_step_callback, until=until_callback)
        return self._simgr

    def finish(self, inst, result):
        """Clean up the explore job. Runs in the GUI thread."""
        super(SimgrExploreJob, self).finish(inst, result)
        # TODO: hci: feature #3: Makes this work for more than just the active stash
        self._cleanup_inspect_breakpoints(self._simgr.active)
        self._callback(result)
        if self._simgr.found:
            # TODO: hci: fix?: This will pop up after each explore job if you leave a state in the found stash. Could
            #  potentially be solved by tracking how many states are in the found stash prior to running the
            #  job, then compare to the number of states in the found stash after the job finishes. Only display
            #  message if number of found states has changed
            QMessageBox.information(GlobalInfo.main_window, "State(s) found",
                                    f"Found {len(self._simgr.found)} state(s)")

    def pre_step_callback(self, simgr, stash=None):
        if stash is None:
            stash = simgr.active
        self._step_progress = 0
        self._number_states_to_step = len(stash)
        self._setup_inspect_breakpoints(stash)
        # TODO: hci: feature #3: Make it so all post/pre step callbacks take the stash as an argument
        self._pre_step_callback(simgr)

    def engine_process_callback(self, state):
        self._step_progress += 1
        self._update_status_string(self.make_status_string())

    def make_status_string(self):
        """Create the status string that's displayed in the lower left of the GUI"""
        status_string = f"Exploring: stepping states {self._step_progress}/{self._number_states_to_step} "
        if self._interrupted:
            status_string += "(Stopping at next step)"
        else:
            status_string += "(press Ctrl+C to stop after next step)"
        return status_string

    def keyboard_interrupt(self):
        """Called from GUI thread. Worker thread will check self._interrupted periodically and exit the job early if
        needed. """
        self._interrupted = True

    @classmethod
    def create(cls, simgr, **kwargs):
        def callback(result):
            simgr.am_event(src='job_done', job='explore', result=result)
        return cls(simgr, callback=callback, **kwargs)

    def _update_status_string(self, text):

        def update_progress():
            # Stop flickering by turning off updates during the status text change
            GlobalInfo.main_window.setUpdatesEnabled(False)
            GlobalInfo.main_window.status = text
            GlobalInfo.main_window.setUpdatesEnabled(True)

        gui_thread_schedule(update_progress)

    def _setup_inspect_breakpoints(self, stash):
        self._cleanup_inspect_breakpoints(stash)
        for state in stash:
            state.inspect.b(event_type="engine_process", when="after", action=self.engine_process_callback)

    def _cleanup_inspect_breakpoints(self, stash):
        for state in stash:
            state.inspect.remove_breakpoint("engine_process",
                                            filter_func=lambda bp: bp.action == self.engine_process_callback)
